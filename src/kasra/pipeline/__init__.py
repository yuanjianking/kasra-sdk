"""Detection pipelines for all four detection modes."""

from kasra.pipeline.input_pipeline import InputDetectionPipeline
from kasra.pipeline.output_pipeline import OutputDetectionPipeline
from kasra.pipeline.batch_pipeline import BatchScanPipeline
from kasra.pipeline.behavior_pipeline import BehaviorDetectionPipeline

__all__ = [
    "InputDetectionPipeline",
    "OutputDetectionPipeline",
    "BatchScanPipeline",
    "BehaviorDetectionPipeline",
]
