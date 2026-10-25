package com.flarefitness.backend.entity.siem;

import com.flarefitness.backend.entity.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.LocalDateTime;

@Entity
@Table(name = "siem_ueba_model_jobs")
public class SiemUebaModelJob extends BaseEntity {
    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;
    @Column(name = "worker_job_id", nullable = false, length = 64)
    private String workerJobId;
    @Column(name = "model_version", nullable = false, length = 64)
    private String modelVersion;
    @Column(name = "requested_by_user_id", nullable = false, length = 64)
    private String requestedByUserId;
    @Column(name = "training_from", nullable = false)
    @UtcDateTime
    private LocalDateTime trainingFrom;
    @Column(name = "training_to", nullable = false)
    @UtcDateTime
    private LocalDateTime trainingTo;
    @Column(name = "training_windows", nullable = false)
    private int trainingWindows;
    @Column(name = "calibration_windows", nullable = false)
    private int calibrationWindows;
    @Column(name = "status", nullable = false, length = 24)
    private String status;
    @Column(name = "data_provenance", nullable = false, length = 16)
    private String dataProvenance = "UNKNOWN";
    @Column(name = "feature_schema_version", nullable = false)
    private int featureSchemaVersion = 1;
    @Column(name = "recipe_id", nullable = false, length = 96)
    private String recipeId = "legacy-v1";
    @Column(name = "dataset_id", length = 64)
    private String datasetId;
    @Column(name = "dataset_manifest_sha256", length = 64)
    private String datasetManifestSha256;
    @Column(name = "model_sha256", length = 64)
    private String modelSha256;
    @Column(name = "evaluation_worker_job_id", length = 64)
    private String evaluationWorkerJobId;
    @Column(name = "evaluation_dataset_id", length = 64)
    private String evaluationDatasetId;
    @Column(name = "evaluation_dataset_sha256", length = 64)
    private String evaluationDatasetSha256;
    @Column(name = "evaluation_status", nullable = false, length = 24)
    private String evaluationStatus = "NOT_RUN";
    @Column(name = "quality_gate", nullable = false, length = 24)
    private String qualityGate = "NOT_RUN";
    @Column(name = "evaluation_summary_json", columnDefinition = "TEXT")
    private String evaluationSummaryJson;
    @Column(name = "activation_worker_job_id", length = 32)
    private String activationWorkerJobId;
    @Column(name = "activation_status", nullable = false, length = 24)
    private String activationStatus = "NOT_RUN";
    @Column(name = "activation_requested_by_user_id", length = 64)
    private String activationRequestedByUserId;
    @Column(name = "activated_at")
    @UtcDateTime
    private LocalDateTime activatedAt;
    @Column(name = "activated_by_user_id", length = 64)
    private String activatedByUserId;
    @Column(name = "updated_at", nullable = false)
    @UtcDateTime
    private LocalDateTime updatedAt;
    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    public String getId() { return id; }
    public void setId(String value) { id = value; }
    public String getWorkerJobId() { return workerJobId; }
    public void setWorkerJobId(String value) { workerJobId = value; }
    public String getModelVersion() { return modelVersion; }
    public void setModelVersion(String value) { modelVersion = value; }
    public String getRequestedByUserId() { return requestedByUserId; }
    public void setRequestedByUserId(String value) { requestedByUserId = value; }
    public LocalDateTime getTrainingFrom() { return trainingFrom; }
    public void setTrainingFrom(LocalDateTime value) { trainingFrom = value; }
    public LocalDateTime getTrainingTo() { return trainingTo; }
    public void setTrainingTo(LocalDateTime value) { trainingTo = value; }
    public int getTrainingWindows() { return trainingWindows; }
    public void setTrainingWindows(int value) { trainingWindows = value; }
    public int getCalibrationWindows() { return calibrationWindows; }
    public void setCalibrationWindows(int value) { calibrationWindows = value; }
    public String getStatus() { return status; }
    public void setStatus(String value) { status = value; }
    public String getDataProvenance() { return dataProvenance; }
    public void setDataProvenance(String value) { dataProvenance = value; }
    public int getFeatureSchemaVersion() { return featureSchemaVersion; }
    public void setFeatureSchemaVersion(int value) { featureSchemaVersion = value; }
    public String getRecipeId() { return recipeId; }
    public void setRecipeId(String value) { recipeId = value; }
    public String getDatasetId() { return datasetId; }
    public void setDatasetId(String value) { datasetId = value; }
    public String getDatasetManifestSha256() { return datasetManifestSha256; }
    public void setDatasetManifestSha256(String value) { datasetManifestSha256 = value; }
    public String getModelSha256() { return modelSha256; }
    public void setModelSha256(String value) { modelSha256 = value; }
    public String getEvaluationWorkerJobId() { return evaluationWorkerJobId; }
    public void setEvaluationWorkerJobId(String value) { evaluationWorkerJobId = value; }
    public String getEvaluationDatasetId() { return evaluationDatasetId; }
    public void setEvaluationDatasetId(String value) { evaluationDatasetId = value; }
    public String getEvaluationDatasetSha256() { return evaluationDatasetSha256; }
    public void setEvaluationDatasetSha256(String value) { evaluationDatasetSha256 = value; }
    public String getEvaluationStatus() { return evaluationStatus; }
    public void setEvaluationStatus(String value) { evaluationStatus = value; }
    public String getQualityGate() { return qualityGate; }
    public void setQualityGate(String value) { qualityGate = value; }
    public String getEvaluationSummaryJson() { return evaluationSummaryJson; }
    public void setEvaluationSummaryJson(String value) { evaluationSummaryJson = value; }
    public String getActivationWorkerJobId() { return activationWorkerJobId; }
    public void setActivationWorkerJobId(String value) { activationWorkerJobId = value; }
    public String getActivationStatus() { return activationStatus; }
    public void setActivationStatus(String value) { activationStatus = value; }
    public String getActivationRequestedByUserId() { return activationRequestedByUserId; }
    public void setActivationRequestedByUserId(String value) { activationRequestedByUserId = value; }
    public LocalDateTime getActivatedAt() { return activatedAt; }
    public void setActivatedAt(LocalDateTime value) { activatedAt = value; }
    public String getActivatedByUserId() { return activatedByUserId; }
    public void setActivatedByUserId(String value) { activatedByUserId = value; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime value) { updatedAt = value; }
}
