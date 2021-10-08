import requests
import json
import time
import pickle
from models.Filter import Filter
from models.Issue import Issue
from models.Project import Project
from models.Rule import Rule


def get_rules(filter: Filter):
    get_rules_url = f'https://sonarcloud.io/api/rules/search?organization={filter.organization}&p=1&ps=500&languages={filter.languages}&statuses=READY&types={filter.rule_types}'
    response = json.loads(requests.get(get_rules_url, auth=sonar_auth).text)

    rules = []
    for rule in response['rules']:
        rules.append(Rule(rule.get('type'), rule.get('key'), rule.get('name'), rule.get('severity')))

    return rules


def get_projects(filter: Filter) -> None:
    projects = []
    loop = True
    page_number = 1
    count = 1;

    while loop:
        url_get_all_projects = f'https://sonarcloud.io/api/components/search_projects?ps=500&p={page_number}&filter=ncloc >= {filter.project_min_size} and ncloc <= {filter.project_max_size} and languages = {filter.languages}'
        response = json.loads(requests.get(url_get_all_projects, auth=sonar_auth).text)


        for project in response['components']:
            if 'part' in project["name"].strip().lower() and 'unlimit' in project["name"].strip().lower():
                continue

            url_get_project_metrics = f'https://sonarcloud.io/api/measures/component?component={project["key"]}&metricKeys=lines,ncloc,ncloc_language_distribution,classes,line_coverage,bugs,code_smells,vulnerabilities,security_hotspots,duplicated_lines'
            response_metrics = json.loads(requests.get(url_get_project_metrics, auth=sonar_auth).text)

            projects.append(
                Project(
                    project['organization'],
                    project['key'],
                    project['name'],
                    next((int(x['value']) for x in response_metrics['component']['measures'] if x['metric'] == 'lines'), 0),
                    next((int(x['value']) for x in response_metrics['component']['measures'] if x['metric'] == 'ncloc'), 0),
                    extract_list(next(x['value'] for x in response_metrics['component']['measures'] if x['metric'] == 'ncloc_language_distribution')),
                    next((int(x['value']) for x in response_metrics['component']['measures'] if x['metric'] == 'classes'), 0),
                    next((float(x['value']) for x in response_metrics['component']['measures'] if x['metric'] == 'line_coverage'), 0.0)))

            print(f'{count} - Got metrics for project {project["name"]} successfully!')
            count = count + 1

        if (response['paging']['pageIndex'] * response['paging']['pageSize']) >= response['paging']['total']:
            loop = False
        else:
            page_number = page_number + 1

    return projects


def extract_list(str):
    spplited = str.split(';')
    for val in spplited:
        specific = val.split('=')
        if specific[0] == 'cs':
            return int(specific[1])

    return 0


def fill_project_issues(records: list[Project], filter: Filter, issue_type, issue_property):
    for rec in records:
        loop = True
        page_number = 1
        count = 1

        project_issues = []
        while loop:
            try:
                project_issues_url = f'https://sonarcloud.io/api/issues/search?componentKeys={rec.projectKey}&p={page_number}&ps=500&types={issue_type}&languages={filter.languages}&statuses={filter.issue_status}'
                response = json.loads(requests.get(project_issues_url, auth=sonar_auth).text)

                for issue in response.get('issues'):
                    project_issues.append(
                        Issue(issue.get('rule'), issue.get('message'), issue.get('severity')))

                if (response['p'] * response['ps']) >= response['total']:
                    loop = False
                    setattr(rec, issue_property, project_issues)
                else:
                    page_number = page_number + 1
                    time.sleep(0.05)
            except:
                loop = False
                print("An exception occurred")

        print(f'{count} - All issues of type {issue_type} were successfully collected for project {rec.projectKey}!')
        count = count + 1


sonar_auth = ("PUT_YOUR_SECRET_HERE", "")


if __name__ == '__main__':
    filter = Filter('explore', 'cs', 'CODE_SMELL,BUG,VULNERABILITY,', 'OPEN,CONFIRMED,REOPENED', 50000, 10000000)

    rules = get_rules(filter)
    with open('venv/rules.dat', 'wb') as f:
        pickle.dump(rules, f)

    projects = get_projects(filter)
    fill_project_issues(projects, filter, 'BUG', 'bugs')
    fill_project_issues(projects, filter, 'CODE_SMELL', 'code_smells')
    fill_project_issues(projects, filter, 'VULNERABILITY', 'vulnerabilities')

    with open('venv/projects.dat', 'wb') as f:
        pickle.dump(projects, f)
