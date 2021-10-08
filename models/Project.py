class Project:
    def __init__(self, organization, project_key, project_name, lines, lines_of_code, lines_of_code_per_language, classes, line_coverage):
        self.projectOrganization = organization
        self.projectKey = project_key
        self.projectName = project_name
        self.metrics_lines = lines
        self.metrics_lines_of_code = lines_of_code
        self.metrics_lines_of_code_per_language = lines_of_code_per_language
        self.metrics_classes = classes
        self.metrics_line_coverage = line_coverage
        self.code_smells = []
        self.vulnerabilities = []
        self.bugs = []
