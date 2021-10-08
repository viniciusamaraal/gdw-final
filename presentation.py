import pandas as pd
import pickle
import json
import jsonpickle
import matplotlib.pyplot as plt
from models.Issue import Issue
from models.Project import Project


class Parameter:
    def __init__(self, key, value):
        self.key = key
        self.value = value


def load_projects():
    with open('venv/projects.dat', 'rb') as f:
        json_str = jsonpickle.encode(pickle.load(f), unpicklable=False)
        return json.loads(json_str)


def visualize_severity(df_bugs, df_code_smells, df_vulnerabilities):
    labels = ['BLOCKER', 'CRITICAL', 'INFO', 'MAJOR', 'MINOR']
    colors = ['m', 'r', 'c', 'y', 'g']
    bugs = df_bugs.groupby(['severity']).size().array
    code_smells = df_code_smells.groupby(['severity']).size().array
    vulnerabilities = df_vulnerabilities.groupby(['severity']).size().array

    print(df_bugs.groupby(['severity']).size())
    print(df_code_smells.groupby(['severity']).size())
    print(df_vulnerabilities.groupby(['severity']).size())

    df = pd.DataFrame({'bugs': bugs, 'code_smells': code_smells, 'vulnerabilities': vulnerabilities})

    fig, axs = plt.subplots(ncols=3, nrows=1)
    axs[0].pie(df['bugs'], autopct=lambda p: '{0:.2f}%'.format(p) if p > 0.5 else '', textprops={'fontsize': 20},
               colors=colors)
    axs[0].set_title('Bugs')

    axs[1].pie(df['code_smells'], autopct=lambda p: '{0:.2f}%'.format(p) if p > 0.5 else '', textprops={'fontsize': 20},
               colors=colors)
    axs[1].set_title('Code Smells')

    axs[2].pie(df['vulnerabilities'], autopct=lambda p: '{0:.2f}%'.format(p) if p > 0.5 else '',
               textprops={'fontsize': 20}, colors=colors)
    axs[2].set_title('Vulnerabilidades')
    fig.legend(labels=labels, loc='upper center')
    plt.show()


def visualize_critical(df_bugs, df_code_smells, df_vulnerabilities):
    bugs = df_bugs.query('severity == "CRITICAL"').groupby(['rule']).size()
    code_smells = df_code_smells.query('severity == "CRITICAL"').groupby(['rule']).size()
    vulnerabilities = df_vulnerabilities.query('severity == "CRITICAL"').groupby(['rule']).size()

    print(bugs.sort_values())
    print(code_smells.sort_values())
    print(vulnerabilities.sort_values())


if __name__ == '__main__':
    projects = load_projects()

    df_metrics = pd.json_normalize(projects, max_level=0)
    df_bugs = pd.json_normalize(
        projects, record_path='bugs', meta=['projectOrganization', 'projectKey', 'projectName'])
    df_code_smells = pd.json_normalize(
        projects, record_path='code_smells', meta=['projectOrganization', 'projectKey', 'projectName'])
    df_vulnerabilities = pd.json_normalize(
        projects, record_path='vulnerabilities', meta=['projectOrganization', 'projectKey', 'projectName'])

    print(f'loc {df_metrics.metrics_lines_of_code_per_language.sum()}')
    print(f'classes {df_metrics.metrics_classes.sum()}')

    visualize_severity(df_bugs, df_code_smells, df_vulnerabilities)
    visualize_critical(df_bugs, df_code_smells, df_vulnerabilities)
