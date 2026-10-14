package consensus

import (
	"context"
	"math/rand"
	"time"
)

func (e *ConsensusEngine) runLoop() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		e.mu.RLock()
		role := e.role
		e.mu.RUnlock()

		switch role {
		case RoleLeader:
			e.broadcastAppendEntries()
			select {
			case <-e.stopCh:
				return
			case <-e.proposeCh:
			case <-time.After(e.heartbeatPeriod):
			}
		case RoleFollower, RoleCandidate:
			timeout := e.electionTimeout + time.Duration(r.Int63n(int64(e.electionTimeout)))
			select {
			case <-e.stopCh:
				return
			case <-e.proposeCh:
				// Woken up due to state change
			case <-time.After(timeout):
				e.mu.Lock()
				if time.Since(e.lastHeartbeat) >= e.electionTimeout {
					e.startElection()
				}
				e.mu.Unlock()
			}
		}
	}
}

func (e *ConsensusEngine) startElection() {
	e.role = RoleCandidate
	e.currentTerm++
	e.votedFor = e.nodeID
	e.lastHeartbeat = time.Now()

	totalNodes := len(e.peers) + 1
	quorumNeeded := (totalNodes / 2) + 1

	if totalNodes == 1 {
		e.role = RoleLeader
		e.leaderID = e.nodeID
		select {
		case e.proposeCh <- struct{}{}:
		default:
		}
		return
	}

	votesReceived := 1
	lastLogIndex := uint64(len(e.log) - 1)
	lastLogTerm := e.log[lastLogIndex].Term
	req := VoteRequest{
		Term:         e.currentTerm,
		CandidateID:  e.nodeID,
		LastLogIndex: lastLogIndex,
		LastLogTerm:  lastLogTerm,
	}

	if e.rpcTransport == nil {
		return
	}

	for _, peer := range e.peers {
		p := peer
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), e.electionTimeout/2)
			defer cancel()
			res, err := e.rpcTransport.RequestVote(ctx, p, req)
			if err != nil || res == nil {
				return
			}

			e.mu.Lock()
			defer e.mu.Unlock()

			if res.Term > e.currentTerm {
				e.currentTerm = res.Term
				e.role = RoleFollower
				e.votedFor = ""
				return
			}

			if e.role == RoleCandidate && res.Term == e.currentTerm && res.VoteGranted {
				votesReceived++
				if votesReceived >= quorumNeeded {
					e.role = RoleLeader
					e.leaderID = e.nodeID
					select {
					case e.proposeCh <- struct{}{}:
					default:
					}
					go e.broadcastAppendEntries()
				}
			}
		}()
	}
}
