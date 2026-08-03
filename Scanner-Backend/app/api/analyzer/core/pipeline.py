from core.schemas import AnalyserResult, PipelineResult
from controllers.dns_scoring import DNSScoringAnalyser

class AnalyserPipeline:
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.domain = raw_data.get("domain", "unknown")

    def run(self):
        pipeline_result = PipelineResult()
        analyser_result = AnalyserResult()

        # print("Running analyser pipeline with raw data:", self.raw_data)

        pipeline = [
            DNSScoringAnalyser(self.raw_data, self.domain),
        ]

        for analyser in pipeline:
            # print(f"Running analyser: {analyser.__class__.__name__}")
            category_result = analyser.run()
            # print(f"Result from {analyser.__class__.__name__}: {analyser_result}")
            pipeline_result.penalty_score += category_result.penalty_score
            pipeline_result.details[category_result.category] = category_result.details

        analyser_result.score -= pipeline_result.penalty_score
        analyser_result.result = pipeline_result.details
        analyser_result.domain = self.domain

        return analyser_result




