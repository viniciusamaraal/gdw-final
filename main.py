import requests
import json
import time
import pandas as pd

sonar_auth = ("1e83fe8218145c70eff585c0fc08bf04df4aa89b", "")


class Filter:
    def __init__(self, languages, size):
        self.languages = languages
        self.size = size


class Record:
    def __init__(self, organization, project_key, project_name):
        self.projectOrganization = organization
        self.projectKey = project_key
        self.projectName = project_name
        self.code_smells = []
        self.bugs = []


class Issue:
    def __init__(self, key, rule, severity, message, effort, debt, assignee):
        self.key = key
        self.rule = rule
        self.severity = severity
        self.message = message
        self.effort = effort
        self.debt = debt
        self.assignee = assignee


def get_all_projects(records: list, filter: Filter) -> None:
    url_get_all_projects = f'https://sonarcloud.io/api/components/search_projects?ps=300&filter=ncloc >= {filter.size} and languages = {filter.languages}'
    response = json.loads(requests.get(url_get_all_projects, auth=sonar_auth).text)

    for project in response['components']:
        records.append(Record(project['organization'], project['key'], project['name']))


def fill_project_code_smells(records: list[Record], filter: Filter, type, property_name):
    for rec in records:
        loop = True
        page_number = 1

        project_issues = []
        while loop:
            url_get_project_issues = f'https://sonarcloud.io/api/issues/search?componentKeys={rec.projectKey}&p={page_number}&faceMode=effort&faces=types&ps=500&types={type}'
            response = json.loads(requests.get(url_get_project_issues, auth=sonar_auth).text)

            for issue in response['issues']:
                project_issues.append(Issue(issue.get('key'), issue.get('rule'), issue.get('severity'), issue.get('message'), issue.get('effort'), issue.get('debt'), issue.get('assignee')))

            if (response['p'] * response['ps']) >= response['total']:
                loop = False
                setattr(rec, property_name, project_issues)
            else:
                page_number = page_number + 1
                time.sleep(0.05)

        print(f'{type} for project {rec.projectKey} done!')


if __name__ == '__main__':
    records: list = []
    filter = Filter('cs', 100000)

    get_all_projects(records, filter)
    fill_project_code_smells(records, filter, 'CODE_SMELL', 'code_smells')
    fill_project_code_smells(records, filter, 'BUG', 'bugs')

    print('done!')