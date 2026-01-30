import os
import sys
import subprocess


def create_venv_and_install(requirements_file: str) -> None:
    """
    creates virtual environment and installs requirements.txt file
    :param requirements_file:
    :return:
    """
    # Define the virtual environment name or path
    venv_dir: str = 'venv'

    # Create the virtual environment
    print("Creating virtual environment...")
    subprocess.run([sys.executable, '-m', 'venv', venv_dir])

    # Determine the pip executable path
    if os.name == 'nt':  # Windows
        pip_executable = os.path.join(venv_dir, 'Scripts', 'pip.exe')
    else:  # Linux/Mac
        pip_executable = os.path.join(venv_dir, 'bin', 'pip')

    # Install libraries from requirements.txt
    if os.path.isfile(requirements_file):
        print("Installing libraries from requirements.txt...")
        subprocess.run([pip_executable, 'install', '-r', requirements_file])
    else:
        print(f"Requirements file '{requirements_file}' not found.")

    print(f"Virtual environment created at {venv_dir} and libraries installed (if any).")


if __name__ == '__main__':
    requirements_file = 'requirements.txt'  # Change this if your file is named differently
    create_venv_and_install(requirements_file)
