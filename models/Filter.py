class Filter:
    def __init__(self, organization, languages, types, issue_status, project_min_size, project_max_size):
        self.organization = organization
        self.languages = languages
        self.rule_types = types
        self.issue_status = issue_status
        self.project_min_size = project_min_size
        self.project_max_size = project_max_size
