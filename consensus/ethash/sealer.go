// Copyright 2017 The go-ethereum Authors
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

package ethash

import (
	crand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the block's difficulty requirements.
// 挖矿处理: 尝试找到一个满足块难度需求的nonce值.
func (ethash *Ethash) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	// If we're running a fake PoW, simply return a 0 nonce immediately
	// 如果关闭POW, 则立即返回值为0的nonce.
	if ethash.config.PowMode == ModeFake || ethash.config.PowMode == ModeFullFake {
		header := block.Header()
		header.Nonce, header.MixDigest = types.BlockNonce{}, common.Hash{}
		return block.WithSeal(header), nil
	}
	// If we're running a shared PoW, delegate sealing to it
	// 如果开启共享POW模式, 则委托挖矿.
	if ethash.shared != nil {
		return ethash.shared.Seal(chain, block, stop)
	}
	// 如果开启正常POW模式, 则自己挖矿.

	// Create a runner and the multiple search threads it directs
	// 产生多个线程同时挖矿
	abort := make(chan struct{})
	found := make(chan *types.Block)

	ethash.lock.Lock()
	threads := ethash.threads
	if ethash.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			ethash.lock.Unlock()
			return nil, err
		}
		ethash.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	ethash.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}
	var pend sync.WaitGroup
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func(id int, nonce uint64) {
			defer pend.Done()
			ethash.mine(block, id, nonce, abort, found)
		}(i, uint64(ethash.rand.Int63()))
	}
	// Wait until sealing is terminated or a nonce is found
	// 等待: 直到挖矿终止或找到一个nonce值.
	var result *types.Block
	select {
	case <-stop:
		// Outside abort, stop all miner threads
		// 外部终止, 终止所有挖矿协程
		close(abort)
	case result = <-found:
		// One of the threads found a block, abort all others
		// 挖矿成功, 终止所有挖矿协程
		close(abort)
	case <-ethash.update:
		// Thread count was changed on user request, restart
		// 线程数量发生改变, 重新挖矿
		close(abort)
		pend.Wait()
		return ethash.Seal(chain, block, stop)
	}
	// Wait for all miners to terminate and return the block
	pend.Wait() // 等待所有矿工终止, 并返回块对象
	return result, nil
}

// mine is the actual proof-of-work miner that searches for a nonce starting from
// seed that results in correct final block difficulty.
// mine: 实际的POW矿工, 该方法用于从seed开始搜索一个满足块难度的nonce值
func (ethash *Ethash) mine(block *types.Block, id int, seed uint64, abort chan struct{}, found chan *types.Block) {
	// Extract some data from the header 从header提取一些数据.
	var (
		header  = block.Header()                                  // 头部信息
		hash    = header.HashNoNonce().Bytes()                    // 哈希值(无NONCE时)
		target  = new(big.Int).Div(maxUint256, header.Difficulty) // 相除
		number  = header.Number.Uint64()                          // 块号
		dataset = ethash.dataset(number)                          // 数据集合
	)
	// Start generating random nonces until we abort or find a good one
	// 开始生成随机nonce知道我们终止或找到一个正确值.
	var (
		attempts = int64(0)
		nonce    = seed
	)
	logger := log.New("miner", id)
	logger.Trace("Started ethash search for new nonces", "seed", seed)
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			// 挖矿终止: 更新状态并终止.
			logger.Trace("Ethash nonce search aborted", "attempts", nonce-seed)
			ethash.hashrate.Mark(attempts)
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			// 我们不必为每个nonce更新hash rate, 每2^X更新一次.
			attempts++
			if (attempts % (1 << 15)) == 0 {
				ethash.hashrate.Mark(attempts)
				attempts = 0
			}
			// Compute the PoW value of this nonce
			digest, result := hashimotoFull(dataset.dataset, hash, nonce)
			if new(big.Int).SetBytes(result).Cmp(target) <= 0 {
				// Correct nonce found, create a new header with it
				// 找到正确的nonce值, 为其创建一个新的头部.
				header = types.CopyHeader(header)
				header.Nonce = types.EncodeNonce(nonce)
				header.MixDigest = common.BytesToHash(digest)

				// Seal and return a block (if still needed)
				select {
				case found <- block.WithSeal(header):
					logger.Trace("Ethash nonce found and reported", "attempts", nonce-seed, "nonce", nonce)
				case <-abort:
					logger.Trace("Ethash nonce found but discarded", "attempts", nonce-seed, "nonce", nonce)
				}
				break search
			}
			nonce++
		}
	}
	// Datasets are unmapped in a finalizer. Ensure that the dataset stays live
	// during sealing so it's not unmapped while being read.
	runtime.KeepAlive(dataset)
}
