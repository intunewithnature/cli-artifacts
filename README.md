# cli-artifacts

Windows Event Log parser for people who hate Event Viewer.

## Usage

```bash
pip install -r requirements.txt
python artifacts.py System.evtx
python artifacts.py System.evtx --level error
python artifacts.py System.evtx --output results.csv
python artifacts.py System.evtx --summary
```
