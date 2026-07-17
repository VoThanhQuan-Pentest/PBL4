package com.flarefitness.backend.repository;

import com.flarefitness.backend.entity.Customer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CustomerRepository extends JpaRepository<Customer, String> {

    Optional<Customer> findFirstBySdt(String sdt);

    @Query("""
            select count(c) > 0 from Customer c
            where c.sdt in :phoneNumbers
              and (c.deleted = false or c.deleted is null)
            """)
    boolean existsActiveBySdtIn(@Param("phoneNumbers") Collection<String> phoneNumbers);

    @Query("""
            select count(c) > 0 from Customer c
            where c.sdt in :phoneNumbers
              and (c.userId is null or c.userId <> :userId)
              and (c.deleted = false or c.deleted is null)
            """)
    boolean existsActiveBySdtInAndUserIdNot(
            @Param("phoneNumbers") Collection<String> phoneNumbers,
            @Param("userId") String userId
    );

    /**
     * Returns a profile only when the legacy data has one unambiguous active
     * customer record for the immutable user id.  This prevents a duplicate
     * historical link from selecting an arbitrary customer's PII.
     */
    @Query("""
            select c from Customer c
            where c.userId = :userId
              and (c.deleted = false or c.deleted is null)
              and 1 = (
                  select count(other) from Customer other
                  where other.userId = :userId
                    and (other.deleted = false or other.deleted is null)
              )
            """)
    Optional<Customer> findUniqueActiveByUserId(@Param("userId") String userId);

    @Query("""
            select c from Customer c
            where c.userId = :userId
              and 1 = (
                  select count(other) from Customer other
                  where other.userId = :userId
              )
            """)
    Optional<Customer> findUniqueByUserId(@Param("userId") String userId);

    @Query("""
            select c from Customer c
            where c.userId in :userIds
              and (c.deleted = false or c.deleted is null)
            """)
    List<Customer> findActiveByUserIdIn(@Param("userIds") Collection<String> userIds);

    @Query("""
            select c from Customer c
            where lower(c.email) = lower(:email)
              and (c.deleted = false or c.deleted is null)
            order by c.id asc
            """)
    List<Customer> findActiveByEmailIgnoreCase(@Param("email") String email);

}
