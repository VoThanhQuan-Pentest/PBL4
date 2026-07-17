package com.flarefitness.backend.repository.sync;

import com.flarefitness.backend.entity.sync.SyncState;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SyncStateRepository extends JpaRepository<SyncState, String> {

    Optional<SyncState> findByScopeAndOwnerIdAndKeyName(String scope, String ownerId, String keyName);

    Optional<SyncState> findByScopeAndKeyNameAndOwnerIdIsNull(String scope, String keyName);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select state from SyncState state
            where state.scope = :scope
              and state.ownerId = :ownerId
              and state.keyName = :keyName
            """)
    Optional<SyncState> findByScopeAndOwnerIdAndKeyNameForUpdate(
            @Param("scope") String scope,
            @Param("ownerId") String ownerId,
            @Param("keyName") String keyName
    );
}
