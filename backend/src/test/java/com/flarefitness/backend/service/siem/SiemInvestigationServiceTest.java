package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.exception.BadRequestException;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

class SiemInvestigationServiceTest {
    final SiemWorkspaceService workspace=mock(SiemWorkspaceService.class);
    final SiemEvidenceService evidence=mock(SiemEvidenceService.class);
    final SiemContainmentService containment=mock(SiemContainmentService.class);
    final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    final SiemInvestigationService service=new SiemInvestigationService(workspace,evidence,containment,jdbc,new ObjectMapper());
    @BeforeEach void scope(){when(workspace.scope(anyString(),eq(100))).thenAnswer(call->new SiemWorkspaceService.EvidenceScope(mock(SiemDtos.Incident.class),new SiemEvidenceService.Filter(LocalDateTime.now().minusDays(1),LocalDateTime.now(),null,null,null,null,100),Set.of("logs-flare.security-lab\nref"),Set.of(),false));}
    @AfterEach void cleanup(){SecurityContextHolder.clearContext();}
    @Test void fixtureKeepsWorkflowSourceWithoutInventingAnElkDocument(){
        var incident=mock(SiemDtos.Incident.class);when(incident.sourceIp()).thenReturn("192.0.2.25");when(incident.targetUserId()).thenReturn("practice-customer");
        var scope=new SiemWorkspaceService.EvidenceScope(incident,new SiemEvidenceService.Filter(LocalDateTime.now().minusHours(1),LocalDateTime.now(),null,null,"192.0.2.25",null,50),Set.of(),Set.of(),true);
        when(workspace.scope("fixture",50)).thenReturn(scope);when(containment.list("fixture")).thenReturn(List.of());
        var result=service.summary("fixture");assertThat(result.workflowContext()).containsEntry("source_ip","192.0.2.25");assertThat(result.observed()).isEmpty();assertThat(result.sourceStatus()).isEqualTo("NO_DETECTION_LOG");verifyNoInteractions(evidence);
    }
    @Test void sourceTimestampIsOptInSoExistingEvidenceClientsKeepTheirOriginalContract(){
        var incident=mock(SiemDtos.Incident.class);when(incident.id()).thenReturn("case");
        var scope=new SiemWorkspaceService.EvidenceScope(incident,new SiemEvidenceService.Filter(LocalDateTime.now().minusHours(1),LocalDateTime.now(),null,null,null,null,50),Set.of(),Set.of("event"),false);
        var at=LocalDateTime.of(2026,10,23,12,0);
        var aggregate=new SiemEvidenceService.Aggregate(Map.of(),"AVAILABLE",at);
        when(workspace.scope("case",50)).thenReturn(scope);when(evidence.aggregate(any(),anySet(),anySet())).thenReturn(aggregate);
        when(containment.list("case")).thenReturn(List.of());when(evidence.aggregateBatch(anyMap())).thenReturn(Map.of("case",aggregate));
        assertThat(service.summary("case").firstObservedAt()).isNull();assertThat(service.summary("case",true).firstObservedAt()).isEqualTo(at);
        assertThat(service.queue(List.of(incident)).getFirst().firstObservedAt()).isNull();assertThat(service.queue(List.of(incident),true).getFirst().firstObservedAt()).isEqualTo(at);
    }
    @SuppressWarnings("unchecked")
    void workflowNotes(int count){
        when(jdbc.query(anyString(),any(RowMapper.class),any(),any())).thenAnswer(call->{
            if(!call.getArgument(0,String.class).contains("siem_incident_notes"))return List.of();
            RowMapper<?> mapper=call.getArgument(1);List<Object> refs=new ArrayList<>();
            for(int i=0;i<count;i++){ResultSet row=mock(ResultSet.class);when(row.getString(1)).thenReturn("note-"+String.format("%04d",i));when(row.getTimestamp(2)).thenReturn(Timestamp.valueOf(LocalDateTime.now().minusHours(1).withNano(0)));refs.add(mapper.mapRow(row,i));}
            return refs;
        });
        when(jdbc.queryForMap(anyString(),any())).thenAnswer(call->Map.of("author_user_id","l1","content",call.getArgument(1)));
    }
    @Test void workflowRemainsAvailableWhileElasticsearchIsDown(){
        workflowNotes(1);when(evidence.search(any(),isNull(),eq("case"),anySet(),anySet(),eq(false))).thenReturn(new SiemEvidenceService.Page(List.of(),null,"UNAVAILABLE"));
        var result=service.timeline("case",null,null,false,50);assertThat(result.sourceStatus()).isEqualTo("PARTIAL_UNAVAILABLE");assertThat(result.content()).hasSize(1);assertThat(result.content().getFirst().kind()).isEqualTo("NOTE");assertThat(result.content().getFirst().elkHit()).isNull();
    }
    @Test void timelineSnapshotIsPagedWithoutDuplicatesAndAnotherPrincipalCannotConsumeIt(){
        workflowNotes(100);SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("l1",null));
        var first=service.timeline("case",null,"NOTE",false,50);assertThat(first.content()).hasSize(50);assertThat(first.nextCursor()).isNotNull();
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("l2",null));
        assertThatThrownBy(()->service.timeline("case",first.nextCursor(),"NOTE",false,50)).isInstanceOf(BadRequestException.class);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("l1",null));
        var second=service.timeline("case",first.nextCursor(),"NOTE",false,50);
        Set<String> ids=new HashSet<>();first.content().forEach(e->ids.add(e.id()));second.content().forEach(e->ids.add(e.id()));assertThat(ids).hasSize(100);assertThat(second.nextCursor()).isNull();verifyNoInteractions(evidence);
    }
}
