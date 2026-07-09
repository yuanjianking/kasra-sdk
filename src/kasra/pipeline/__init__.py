"""Detection pipelines for all detection modes."""

from kasra.pipeline.input_pipeline import InputDetectionPipeline
from kasra.pipeline.output_pipeline import OutputDetectionPipeline
from kasra.pipeline.behavior_pipeline import BehaviorDetectionPipeline

__all__ = [
    "InputDetectionPipeline",
    "OutputDetectionPipeline",
    "BehaviorDetectionPipeline",
]
