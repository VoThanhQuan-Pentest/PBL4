package com.flarefitness.backend.controller;

import com.flarefitness.backend.dto.common.PageResponse;
import com.flarefitness.backend.dto.siem.SiemDtos;
import com.flarefitness.backend.entity.siem.*;
import com.flarefitness.backend.exception.BadRequestException;
import com.flarefitness.backend.service.siem.*;
import java.time.LocalDateTime;
import java.util.*;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/siem/investigation-queue")
public class SiemInvestigationQueueController {
    private final SiemIncidentService workflow;
    private final SiemInvestigationService investigation;
    public SiemInvestigationQueueController(SiemIncidentService workflow,SiemInvestigationService investigation){this.workflow=workflow;this.investigation=investigation;}
    @GetMapping
    public PageResponse<SiemInvestigationService.QueueEntry> list(@RequestParam(required=false) String ids,
            @RequestParam(defaultValue="false") boolean includeEventTime,
            @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size,
            @RequestParam(required=false) IncidentStatus status,@RequestParam(required=false) IncidentSeverity severity,
            @RequestParam(required=false) IncidentClassification classification,@RequestParam(required=false) SiemDtos.IncidentScope scope,
            @RequestParam(required=false) SiemDtos.IncidentSort sort,@RequestParam(required=false) IncidentQueueTier queueTier,
            @RequestParam(required=false) IncidentOrigin origin,@RequestParam(required=false) String targetUserId,
            @RequestParam(required=false) String assigneeUserId,@RequestParam(defaultValue="false") boolean mine,
            @RequestParam(required=false,name="q") String query,
            @RequestParam(required=false) @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required=false) @DateTimeFormat(iso=DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,Authentication authentication){
        if(size<1||size>100||page<0||page>10000)throw new BadRequestException("Invalid investigation queue page.");
        if(ids!=null){
            List<String> selected=Arrays.stream(ids.split(",")).distinct().toList();
            if(selected.isEmpty()||selected.size()>100||selected.stream().anyMatch(id->!id.matches("[A-Za-z0-9_-]{1,64}")))throw new BadRequestException("Invalid incident identity batch.");
            var content=investigation.queue(selected.stream().map(workflow::incidentProjection).toList(),includeEventTime);
            return new PageResponse<>(content,0,content.size(),content.size(),1,false);
        }
        var found=workflow.findIncidents(page,size,status,severity,classification,scope,sort,query,from,to,queueTier,origin,targetUserId,assigneeUserId,mine,authentication);
        return new PageResponse<>(investigation.queue(found.content(),includeEventTime),found.page(),found.size(),found.totalElements(),found.totalPages(),found.hasNext());
    }
}
