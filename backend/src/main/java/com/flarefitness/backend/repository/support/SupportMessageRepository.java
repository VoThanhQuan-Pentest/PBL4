package com.flarefitness.backend.repository.support;

import com.flarefitness.backend.entity.support.SupportMessage;
import java.util.List;
import java.util.Collection;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SupportMessageRepository extends JpaRepository<SupportMessage, String> {

    List<SupportMessage> findByThreadIdOrderByCreatedAtAsc(String threadId);

    List<SupportMessage> findByThreadIdInOrderByCreatedAtAsc(Collection<String> threadIds);

    List<SupportMessage> findTop50ByThreadIdOrderByCreatedAtDesc(String threadId);

    Page<SupportMessage> findByThreadIdOrderByCreatedAtDesc(String threadId, Pageable pageable);

    /**
     * Returns a bounded recent history for every workspace thread in one query. MySQL 8 supports
     * window functions, avoiding the previous "all messages for 100 threads" load.
     */
    @Query(value = """
            select ranked.id, ranked.thread_id, ranked.sender_type, ranked.sender_user_id,
                   ranked.noi_dung, ranked.ngay_tao
            from (
                select m.id, m.thread_id, m.sender_type, m.sender_user_id, m.noi_dung, m.ngay_tao,
                       row_number() over (
                           partition by m.thread_id
                           order by m.ngay_tao desc, m.id desc
                       ) as row_number_in_thread
                from tbl_tin_nhan_ho_tro m
                where m.thread_id in (:threadIds)
            ) ranked
            where ranked.row_number_in_thread <= :perThreadLimit
            order by ranked.thread_id asc, ranked.ngay_tao asc, ranked.id asc
            """, nativeQuery = true)
    List<SupportMessage> findRecentByThreadIdIn(
            @Param("threadIds") Collection<String> threadIds,
            @Param("perThreadLimit") int perThreadLimit
    );
}
