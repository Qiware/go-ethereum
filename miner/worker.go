// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package miner

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"gopkg.in/fatih/set.v0"
)

const (
	resultQueueSize  = 10
	miningLogAtDepth = 5

	// txChanSize is the size of channel listening to TxPreEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	// chainSideChanSize is the size of channel listening to ChainSideEvent.
	chainSideChanSize = 10
)

// Agent can register themself with the worker
type Agent interface {
	Work() chan<- *Work
	SetReturnCh(chan<- *Result)
	Stop()
	Start()
	GetHashRate() int64
}

// Work is the workers current environment and holds
// all of the current state information
type Work struct {
	config *params.ChainConfig
	signer types.Signer

	state     *state.StateDB // apply state changes here
	ancestors *set.Set       // ancestor set (used for checking uncle parent validity)
	family    *set.Set       // family set (used for checking uncle invalidity)
	uncles    *set.Set       // uncle set
	tcount    int            // tx count in cycle

	Block *types.Block // the new block

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt

	createdAt time.Time
}

type Result struct {
	Work  *Work
	Block *types.Block
}

// worker is the main object which takes care of applying messages to the new state
type worker struct {
	config *params.ChainConfig
	engine consensus.Engine

	mu sync.Mutex

	// update loop
	mux          *event.TypeMux
	txCh         chan core.TxPreEvent
	txSub        event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription
	chainSideCh  chan core.ChainSideEvent
	chainSideSub event.Subscription
	wg           sync.WaitGroup

	agents map[Agent]struct{}
	recv   chan *Result

	eth     Backend
	chain   *core.BlockChain
	proc    core.Validator
	chainDb ethdb.Database

	coinbase common.Address
	extra    []byte

	currentMu sync.Mutex
	current   *Work

	uncleMu        sync.Mutex
	possibleUncles map[common.Hash]*types.Block

	unconfirmed *unconfirmedBlocks // set of locally mined blocks pending canonicalness confirmations

	// atomic status counters
	mining int32
	atWork int32
}

/******************************************************************************
 **函数名称: newWorker
 **功    能: 新建矿工对象
 **输入参数:
 **     config: 配置信息
 **     engine: 共识算法
 **     coinbase: 钱包地址
 **     eth: eth对象
 **     mux:
 **输出参数: NONE
 **返    回: worker对象
 **实现描述:
 **注意事项:
 **作    者: # Xxxxxx.xxx # 2016.10.30 22:32:23 #
 ******************************************************************************/
func newWorker(config *params.ChainConfig, engine consensus.Engine, coinbase common.Address, eth Backend, mux *event.TypeMux) *worker {
	worker := &worker{
		config:         config, // 配置信息
		engine:         engine, // 共识算法
		eth:            eth,    // 全局信息
		mux:            mux,
		txCh:           make(chan core.TxPreEvent, txChanSize),            // 交易队列
		chainHeadCh:    make(chan core.ChainHeadEvent, chainHeadChanSize), // 链头队列
		chainSideCh:    make(chan core.ChainSideEvent, chainSideChanSize),
		chainDb:        eth.ChainDb(),                       // 链数据库(LEVEL-DB)
		recv:           make(chan *Result, resultQueueSize), // 接收队列
		chain:          eth.BlockChain(),                    // 区块链
		proc:           eth.BlockChain().Validator(),        // 校验回调
		possibleUncles: make(map[common.Hash]*types.Block),  // 叔伯块
		coinbase:       coinbase,                            // 收益接收地址
		agents:         make(map[Agent]struct{}),            // 挖矿代理集合
		unconfirmed:    newUnconfirmedBlocks(eth.BlockChain(), miningLogAtDepth),
	}
	// Subscribe TxPreEvent for tx pool 订阅交易事件
	worker.txSub = eth.TxPool().SubscribeTxPreEvent(worker.txCh)
	// Subscribe events for blockchain 订阅区块链的相关事件
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)
	worker.chainSideSub = eth.BlockChain().SubscribeChainSideEvent(worker.chainSideCh)
	go worker.update() // 监听事件: 对感兴趣的消息进行处理.

	go worker.wait()
	worker.commitNewWork()

	return worker
}

func (self *worker) setEtherbase(addr common.Address) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.coinbase = addr
}

func (self *worker) setExtra(extra []byte) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.extra = extra
}

func (self *worker) pending() (*types.Block, *state.StateDB) {
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	if atomic.LoadInt32(&self.mining) == 0 {
		return types.NewBlock(
			self.current.header,
			self.current.txs,
			nil,
			self.current.receipts,
		), self.current.state.Copy()
	}
	return self.current.Block, self.current.state.Copy()
}

func (self *worker) pendingBlock() *types.Block {
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	if atomic.LoadInt32(&self.mining) == 0 {
		return types.NewBlock(
			self.current.header,
			self.current.txs,
			nil,
			self.current.receipts,
		)
	}
	return self.current.Block
}

/* 开始工作 */
func (self *worker) start() {
	self.mu.Lock() // 加锁
	defer self.mu.Unlock()

	atomic.StoreInt32(&self.mining, 1)

	// spin up agents
	for agent := range self.agents {
		agent.Start() // 启动代理
	}
}

func (self *worker) stop() {
	self.wg.Wait()

	self.mu.Lock()
	defer self.mu.Unlock()
	if atomic.LoadInt32(&self.mining) == 1 {
		for agent := range self.agents {
			agent.Stop() // 停止代理
		}
	}
	atomic.StoreInt32(&self.mining, 0)
	atomic.StoreInt32(&self.atWork, 0)
}

func (self *worker) register(agent Agent) {
	self.mu.Lock()
	defer self.mu.Unlock()
	self.agents[agent] = struct{}{}
	agent.SetReturnCh(self.recv)
}

func (self *worker) unregister(agent Agent) {
	self.mu.Lock()
	defer self.mu.Unlock()
	delete(self.agents, agent)
	agent.Stop()
}

/******************************************************************************
 **函数名称: update
 **功    能: 监听事件, 并做更新处理.
 **输入参数:
 **输出参数: NONE
 **返    回:
 **实现描述:
 **注意事项:
 **作    者: # Xxxxxx.xxx # 2016.10.30 22:32:23 #
 ******************************************************************************/
func (self *worker) update() {
	defer self.txSub.Unsubscribe()        // 取消订阅
	defer self.chainHeadSub.Unsubscribe() // 取消订阅
	defer self.chainSideSub.Unsubscribe() // 取消订阅

	for {
		// A real event arrived, process interesting content 处理感兴趣的事件
		select {
		// Handle ChainHeadEvent
		case <-self.chainHeadCh: // 链头
			self.commitNewWork() // 提交新work任务

			// Handle ChainSideEvent
		case ev := <-self.chainSideCh: // 侧块: 更新可能叔伯块集合
			self.uncleMu.Lock()
			self.possibleUncles[ev.Block.Hash()] = ev.Block
			self.uncleMu.Unlock()

		// Handle TxPreEvent
		case ev := <-self.txCh: // 交易事件
			// Apply transaction to the pending state if we're not mining
			// 如果不在挖矿, 则申请交易到pending状态.
			if atomic.LoadInt32(&self.mining) == 0 {
				self.currentMu.Lock()
				acc, _ := types.Sender(self.current.signer, ev.Tx)
				txs := map[common.Address]types.Transactions{acc: {ev.Tx}}
				txset := types.NewTransactionsByPriceAndNonce(self.current.signer, txs)

				// 提交交易
				self.current.commitTransactions(self.mux, txset, self.chain, self.coinbase)
				self.currentMu.Unlock()
			} else {
				// If we're mining, but nothing is being processed, wake on new transactions
				// 如果正在挖矿, 但是没有任何东西处理, 则唤醒一个新的交易集合.
				if self.config.Clique != nil && self.config.Clique.Period == 0 { // POA算法
					// 提交新work任务
					self.commitNewWork() // POA收到交易后, 则立即提交新work任务
				}
			}

		// System stopped 停止
		case <-self.txSub.Err():
			return
		case <-self.chainHeadSub.Err():
			return
		case <-self.chainSideSub.Err():
			return
		}
	}
}

func (self *worker) wait() {
	for {
		mustCommitNewWork := true
		for result := range self.recv { // 从接收队列获取数据
			atomic.AddInt32(&self.atWork, -1)

			if result == nil {
				continue
			}
			block := result.Block
			work := result.Work

			// Update the block hash in all logs since it is now available and not when the
			// receipt/log of individual transactions were created.
			for _, r := range work.receipts { // 获取票据
				for _, l := range r.Logs {
					l.BlockHash = block.Hash()
				}
			}
			for _, log := range work.state.Logs() {
				log.BlockHash = block.Hash()
			}
			stat, err := self.chain.WriteBlockWithState(block, work.receipts, work.state)
			if err != nil {
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			// check if canon block and write transactions
			if stat == core.CanonStatTy {
				// implicit by posting ChainHeadEvent
				mustCommitNewWork = false
			}
			// Broadcast the block and announce chain insertion event
			// 广播块, 并发送链的插入事件
			self.mux.Post(core.NewMinedBlockEvent{Block: block})
			var (
				events []interface{}
				logs   = work.state.Logs()
			)
			events = append(events, core.ChainEvent{Block: block, Hash: block.Hash(), Logs: logs})
			if stat == core.CanonStatTy {
				events = append(events, core.ChainHeadEvent{Block: block})
			}
			self.chain.PostChainEvents(events, logs)

			// Insert the block into the set of pending ones to wait for confirmations
			// 把块插入pending集合, 以等待确认.
			self.unconfirmed.Insert(block.NumberU64(), block.Hash())

			if mustCommitNewWork {
				self.commitNewWork()
			}
		}
	}
}

// push sends a new work task to currently live miner agents.
// 发送一个新的work任务给当前正在运行的挖矿代理
func (self *worker) push(work *Work) {
	if atomic.LoadInt32(&self.mining) != 1 {
		return
	}
	for agent := range self.agents {
		atomic.AddInt32(&self.atWork, 1)
		if ch := agent.Work(); ch != nil {
			ch <- work // 将work放入处理队列
		}
	}
}

// makeCurrent creates a new environment for the current cycle.
func (self *worker) makeCurrent(parent *types.Block, header *types.Header) error {
	state, err := self.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}
	work := &Work{
		config:    self.config,
		signer:    types.NewEIP155Signer(self.config.ChainId),
		state:     state,
		ancestors: set.New(),
		family:    set.New(),
		uncles:    set.New(),
		header:    header,
		createdAt: time.Now(),
	}

	// when 08 is processed ancestors contain 07 (quick block)
	for _, ancestor := range self.chain.GetBlocksFromHash(parent.Hash(), 7) {
		for _, uncle := range ancestor.Uncles() {
			work.family.Add(uncle.Hash())
		}
		work.family.Add(ancestor.Hash())
		work.ancestors.Add(ancestor.Hash())
	}

	// Keep track of transactions which return errors so they can be removed
	work.tcount = 0
	self.current = work
	return nil
}

/******************************************************************************
 **函数名称: commitNewWork
 **功    能: 提交新的工作
 **输入参数:
 **输出参数: NONE
 **返    回:
 **实现描述:
 **注意事项:
 **作    者: # Xxxxxx.xxx # 2016.10.30 22:32:23 #
 ******************************************************************************/
func (self *worker) commitNewWork() {
	self.mu.Lock() // 加&解锁
	defer self.mu.Unlock()
	self.uncleMu.Lock()
	defer self.uncleMu.Unlock()
	self.currentMu.Lock()
	defer self.currentMu.Unlock()

	tstart := time.Now()
	parent := self.chain.CurrentBlock()

	tstamp := tstart.Unix()
	if parent.Time().Cmp(new(big.Int).SetInt64(tstamp)) >= 0 {
		tstamp = parent.Time().Int64() + 1
	}
	// this will ensure we're not going off too far in the future
	if now := time.Now().Unix(); tstamp > now+1 {
		wait := time.Duration(tstamp-now) * time.Second
		log.Info("Mining too far in the future", "wait", common.PrettyDuration(wait))
		time.Sleep(wait)
	}

	num := parent.Number()
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     num.Add(num, common.Big1),
		GasLimit:   core.CalcGasLimit(parent),
		Extra:      self.extra,
		Time:       big.NewInt(tstamp),
	}
	// Only set the coinbase if we are mining (avoid spurious block rewards)
	if atomic.LoadInt32(&self.mining) == 1 {
		header.Coinbase = self.coinbase // 挖矿接收地址
	}

	// 准备挖矿: 计算挖矿难度
	if err := self.engine.Prepare(self.chain, header); err != nil {
		log.Error("Failed to prepare header for mining", "err", err)
		return
	}
	// If we are care about TheDAO hard-fork check whether to override the extra-data or not
	if daoBlock := self.config.DAOForkBlock; daoBlock != nil {
		// Check whether the block is among the fork extra-override range
		limit := new(big.Int).Add(daoBlock, params.DAOForkExtraRange)
		if header.Number.Cmp(daoBlock) >= 0 && header.Number.Cmp(limit) < 0 {
			// Depending whether we support or oppose the fork, override differently
			if self.config.DAOForkSupport {
				header.Extra = common.CopyBytes(params.DAOForkBlockExtra)
			} else if bytes.Equal(header.Extra, params.DAOForkBlockExtra) {
				header.Extra = []byte{} // If miner opposes, don't let it use the reserved extra-data
			}
		}
	}
	// Could potentially happen if starting to mine in an odd state.
	err := self.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}
	// Create the current work task and check any fork transitions needed
	work := self.current
	if self.config.DAOForkSupport && self.config.DAOForkBlock != nil && self.config.DAOForkBlock.Cmp(header.Number) == 0 {
		misc.ApplyDAOHardFork(work.state)
	}
	pending, err := self.eth.TxPool().Pending() // 获取当前可以处理的所有交易.
	if err != nil {
		log.Error("Failed to fetch pending transactions", "err", err)
		return
	}
	// 按照价格对交易进行排序(堆排序)
	txs := types.NewTransactionsByPriceAndNonce(self.current.signer, pending)

	// 提交交易
	work.commitTransactions(self.mux, txs, self.chain, self.coinbase)

	// compute uncles for the new block. 为新块计算叔伯块
	var (
		uncles    []*types.Header
		badUncles []common.Hash
	)
	for hash, uncle := range self.possibleUncles { // 遍历叔伯块
		if len(uncles) == 2 {
			break
		}
		if err := self.commitUncle(work, uncle.Header()); err != nil {
			log.Trace("Bad uncle found and will be removed", "hash", hash)
			log.Trace(fmt.Sprint(uncle))

			badUncles = append(badUncles, hash)
		} else {
			log.Debug("Committing new uncle to block", "hash", hash)
			uncles = append(uncles, uncle.Header())
		}
	}
	for _, hash := range badUncles {
		delete(self.possibleUncles, hash) // 删除可能的叔伯块
	}
	// Create the new block to seal with the consensus engine 创建一个新块
	if work.Block, err = self.engine.Finalize(self.chain, header, work.state, work.txs, uncles, work.receipts); err != nil {
		log.Error("Failed to finalize block for sealing", "err", err)
		return
	}
	// We only care about logging if we're actually mining.
	if atomic.LoadInt32(&self.mining) == 1 {
		log.Info("Commit new mining work", "number", work.Block.Number(), "txs", work.tcount, "uncles", len(uncles), "elapsed", common.PrettyDuration(time.Since(tstart)))
		self.unconfirmed.Shift(work.Block.NumberU64() - 1)
	}
	self.push(work) // 将work任务放入处理队列
}

func (self *worker) commitUncle(work *Work, uncle *types.Header) error {
	hash := uncle.Hash()
	if work.uncles.Has(hash) {
		return fmt.Errorf("uncle not unique")
	}
	if !work.ancestors.Has(uncle.ParentHash) {
		return fmt.Errorf("uncle's parent unknown (%x)", uncle.ParentHash[0:4])
	}
	if work.family.Has(hash) {
		return fmt.Errorf("uncle already in family (%x)", hash)
	}
	work.uncles.Add(uncle.Hash())
	return nil
}

// 提交交易
func (env *Work) commitTransactions(mux *event.TypeMux, txs *types.TransactionsByPriceAndNonce, bc *core.BlockChain, coinbase common.Address) {
	gp := new(core.GasPool).AddGas(env.header.GasLimit)

	var coalescedLogs []*types.Log

	for { // 循环处理每一个交易
		// If we don't have enough gas for any further transactions then we're done
		if gp.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "gp", gp)
			break
		}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek() // 获取下一个交易(价格最高的交易)
		if tx == nil {
			break
		}
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(env.signer, tx) // 获取交易发起者地址
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !env.config.IsEIP155(env.header.Number) {
			log.Trace("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", env.config.EIP155Block)

			txs.Pop() // 弹出堆顶
			continue
		}
		// Start executing the transaction 开始执行交易
		env.state.Prepare(tx.Hash(), common.Hash{}, env.tcount) // 准备环境

		err, logs := env.commitTransaction(tx, bc, coinbase, gp) // 提交交易
		switch err {
		case core.ErrGasLimitReached: // 达到GasLimit限制
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop() // 弹出堆顶

		case core.ErrNonceTooLow: // Nonce太低
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift() // 处理当前账号的下一个交易

		case core.ErrNonceTooHigh: // Nonce太高
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop() // 弹出堆顶

		case nil: // 正常
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift() // 处理当前账号的下一个交易

		default: // 其他错误
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Debug("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift() // 处理当前账号的下一个交易
		}
	}

	if len(coalescedLogs) > 0 || env.tcount > 0 {
		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		go func(logs []*types.Log, tcount int) {
			if len(logs) > 0 {
				mux.Post(core.PendingLogsEvent{Logs: logs})
			}
			if tcount > 0 {
				mux.Post(core.PendingStateEvent{})
			}
		}(cpy, env.tcount)
	}
}

func (env *Work) commitTransaction(tx *types.Transaction, bc *core.BlockChain, coinbase common.Address, gp *core.GasPool) (error, []*types.Log) {
	snap := env.state.Snapshot() // 快照

	// 申请交易
	receipt, _, err := core.ApplyTransaction(env.config, bc, &coinbase, gp, env.state, env.header, tx, &env.header.GasUsed, vm.Config{})
	if err != nil {
		env.state.RevertToSnapshot(snap) // 恢复快照
		return err, nil
	}
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)

	return nil, receipt.Logs
}
