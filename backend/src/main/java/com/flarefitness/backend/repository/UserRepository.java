package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.User;
import java.util.Optional;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, String> {

    Page<User> findAllByOrderByHoTenAsc(Pageable pageable);

    @Query("select u from User u where lower(u.username) = lower(:username) and u.deleted = false")
    Optional<User> findByUsernameIgnoreCase(@Param("username") String username);

    @Query("select u from User u where lower(u.email) = lower(:email) and u.deleted = false")
    Optional<User> findByEmailIgnoreCase(@Param("email") String email);

    @Query("select count(u) > 0 from User u where lower(u.username) = lower(:username) and u.deleted = false")
    boolean existsByUsernameIgnoreCase(@Param("username") String username);

    @Query("select count(u) > 0 from User u where lower(u.username) = lower(:username)")
    boolean existsAnyByUsernameIgnoreCase(@Param("username") String username);

    @Query("select count(u) > 0 from User u where lower(u.email) = lower(:email) and u.deleted = false")
    boolean existsByEmailIgnoreCase(@Param("email") String email);

    @Query("select count(u) > 0 from User u where lower(u.username) = lower(:username) and u.id <> :id and u.deleted = false")
    boolean existsByUsernameIgnoreCaseAndIdNot(@Param("username") String username, @Param("id") String id);

    @Query("select count(u) > 0 from User u where lower(u.email) = lower(:email) and u.id <> :id and u.deleted = false")
    boolean existsByEmailIgnoreCaseAndIdNot(@Param("email") String email, @Param("id") String id);

    @Query("select u from User u where u.id = :id and u.deleted = false")
    Optional<User> findActiveById(@Param("id") String id);

    /** Locks a stable parent row so concurrent first support messages cannot create two threads. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.id = :id and u.deleted = false")
    Optional<User> findActiveByIdForUpdate(@Param("id") String id);

    @Modifying
    @Query(value = """
            UPDATE tbl_tai_khoan_can_dat_lai_mat_khau
            SET reset_completed_at = CURRENT_TIMESTAMP
            WHERE user_id = :userId AND reset_completed_at IS NULL
            """, nativeQuery = true)
    void markPasswordResetCompleted(@Param("userId") String userId);

}
