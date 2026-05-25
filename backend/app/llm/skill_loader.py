from pathlib import Path

def load_skill():
    # Gets the directory of this current python file (app/llm)
    current_dir = Path(__file__).parent
    
    # Navigates up two levels to the 'backend' folder, then into 'skills'
    path = current_dir.parent.parent / "skills" / "vulnerability-remediation.md"
    
    return path.read_text()