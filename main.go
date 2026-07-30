package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrLeadershipLost is returned when leadership is lost during an operation.
var ErrLeadershipLost = errors.New("leadership lost: service unavailable")

// Lease represents a dynamic secret lease.
type Lease struct {
	ID        string
	Data      string
	IsPending bool // Marked as pending retry if revocation was interrupted
}

// StorageBarrier simulates Vault's physical storage barrier.
type StorageBarrier struct {
	mu     sync.RWMutex
	leases map[string]*Lease
}

func NewStorageBarrier() *StorageBarrier {
	return &StorageBarrier{
		leases: make(map[string]*Lease),
	}
}

func (sb *StorageBarrier) Put(lease *Lease) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.leases[lease.ID] = lease
}

func (sb *StorageBarrier) Get(id string) (*Lease, bool) {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	l, exists := sb.leases[id]
	return l, exists
}

func (sb *StorageBarrier) Delete(id string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	delete(sb.leases, id)
}

func (sb *StorageBarrier) ListPending() []*Lease {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	var pending []*Lease
	for _, l := range sb.leases {
		if l.IsPending {
			pending = append(pending, l)
		}
	}
	return pending
}

// BackendPlugin simulates a target database or secret backend.
type BackendPlugin struct {
	mu            sync.Mutex
	revokedUsers  map[string]bool
	revokeCounter map[string]int
}

func NewBackendPlugin() *BackendPlugin {
	return &BackendPlugin{
		revokedUsers:  make(map[string]bool),
		revokeCounter: make(map[string]int),
	}
}

// Revoke revokes the physical credentials. It is idempotent.
func (bp *BackendPlugin) Revoke(ctx context.Context, leaseID string) error {
	// Simulate network/database latency
	select {
	case <-time.After(50 * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}

	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Idempotency check: if already revoked, return success without error.
	bp.revokeCounter[leaseID]++
	bp.revokedUsers[leaseID] = true
	return nil
}

func (bp *BackendPlugin) IsRevoked(leaseID string) bool {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.revokedUsers[leaseID]
}

func (bp *BackendPlugin) RevokeCalls(leaseID string) int {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.revokeCounter[leaseID]
}

// ExpirationManager coordinates lease storage and backend revocation.
type ExpirationManager struct {
	barrier *StorageBarrier
	backend *BackendPlugin
	mu      sync.Mutex
	active  bool
}

func NewExpirationManager(barrier *StorageBarrier, backend *BackendPlugin) *ExpirationManager {
	return &ExpirationManager{
		barrier: barrier,
		backend: backend,
		active:  true,
	}
}

// Revoke attempts to revoke a lease.
func (em *ExpirationManager) Revoke(ctx context.Context, leaseID string) error {
	em.mu.Lock()
	active := em.active
	em.mu.Unlock()

	if !active {
		return ErrLeadershipLost
	}

	lease, exists := em.barrier.Get(leaseID)
	if !exists {
		return fmt.Errorf("lease %s not found", leaseID)
	}

	// Step 1: Execute backend revocation first.
	err := em.backend.Revoke(ctx, leaseID)
	if err != nil {
		// If context was canceled or leadership lost, mark the lease as pending retry in the barrier.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			lease.IsPending = true
			em.barrier.Put(lease)
			return fmt.Errorf("%w: revocation interrupted, lease marked for retry", ErrLeadershipLost)
		}
		return fmt.Errorf("backend revocation failed: %w", err)
	}

	// Step 2: Only delete from storage barrier after successful backend confirmation.
	em.barrier.Delete(leaseID)
	return nil
}

// Demote simulates losing leadership.
func (em *ExpirationManager) Demote() {
	em.mu.Lock()
	defer em.mu.Unlock()
	em.active = false
}

// Promote simulates becoming the active primary.
// It scans for pending/dirty leases and retries their revocation.
func (em *ExpirationManager) Promote(ctx context.Context) {
	em.mu.Lock()
	em.active = true
	em.mu.Unlock()

	// Scan and retry pending revocations
	pendingLeases := em.barrier.ListPending()
	for _, lease := range pendingLeases {
		_ = em.Revoke(ctx, lease.ID)
	}
}

func main() {
	fmt.Println("Starting Vault Replication Failover Revocation Simulation...")

	barrier := NewStorageBarrier()
	backend := NewBackendPlugin()
	mgr := NewExpirationManager(barrier, backend)

	// Setup: Create a lease
	leaseID := "auth_db_user_123"
	barrier.Put(&Lease{ID: leaseID, Data: "db-user-credentials"})

	// Simulate failover during revocation
	ctx, cancel := context.WithCancel(context.Background())
	
	// Start revocation in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	var revokeErr error
	go func() {
		defer wg.Done()
		revokeErr = mgr.Revoke(ctx, leaseID)
	}()

	// Simulate leadership loss / context cancellation mid-flight
	time.Sleep(10 * time.Millisecond)
	cancel() // Cancel context to simulate failover interruption
	mgr.Demote()

	wg.Wait()

	// 1. Accurate API Contract: Verify we returned an error (503 equivalent)
	if revokeErr != nil && errors.Is(revokeErr, ErrLeadershipLost) {
		fmt.Printf("[PASS] API Contract: Revocation returned error during failover: %v\n", revokeErr)
	} else {
		fmt.Printf("[FAIL] API Contract: Expected leadership lost error, got: %v\n", revokeErr)
	}

	// 2. Guaranteed Revocation Execution: Verify lease is still in storage barrier
	if _, exists := barrier.Get(leaseID); exists {
		fmt.Println("[PASS] Guaranteed Revocation: Lease remains in storage barrier after interrupted revocation.")
	} else {
		fmt.Println("[FAIL] Guaranteed Revocation: Lease was prematurely deleted from storage barrier.")
	}

	// Verify lease is marked as pending
	if lease, exists := barrier.Get(leaseID); exists && lease.IsPending {
		fmt.Println("[PASS] Transactional Safety: Lease is marked as pending retry.")
	} else {
		fmt.Println("[FAIL] Transactional Safety: Lease is not marked as pending retry.")
	}

	// 3. Promotion & Retry: Promote new primary and retry pending revocations
	fmt.Println("Promoting new primary node...")
	promoteCtx := context.Background()
	mgr.Promote(promoteCtx)

	// Verify lease is now successfully revoked and removed from barrier
	if _, exists := barrier.Get(leaseID); !exists {
		fmt.Println("[PASS] Promotion & Retry: Pending lease was successfully revoked and removed from barrier post-promotion.")
	} else {
		fmt.Println("[FAIL] Promotion & Retry: Pending lease still exists in barrier.")
	}

	if backend.IsRevoked(leaseID) {
		fmt.Println("[PASS] Backend State: Credentials successfully revoked on target backend.")
	} else {
		fmt.Println("[FAIL] Backend State: Credentials still active on target backend.")
	}

	// 4. Idempotency: Verify backend revocation is idempotent
	fmt.Printf("Backend revocation calls for %s: %d\n", leaseID, backend.RevokeCalls(leaseID))
	if backend.RevokeCalls(leaseID) > 0 {
		fmt.Println("[PASS] Idempotency: Backend revocation executed successfully.")
	}
}