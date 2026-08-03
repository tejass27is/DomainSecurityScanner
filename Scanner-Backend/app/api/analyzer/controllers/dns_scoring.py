from core.schemas import PipelineResult, CategoryResult

class DNSScoringAnalyser:
    def __init__(self, raw_data, domain: str):
        self.raw_data = raw_data
        self.category = "DNS Security" 
        self.domain = domain

    def run(self):
        dns_result = CategoryResult()

        dns_result.penalty_score = 50
        dns_result.category = self.category
        dns_result.details = {
            "A": 0,
            "AAAA": 0,
            "CNAME": 0,
            "MX": 0,
            "TXT": 0,
        }

        return dns_result