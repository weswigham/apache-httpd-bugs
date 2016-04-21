# apache-httpd-bugs
Processes apache httpd bugs and links them up to the commits they were fixed in

## Usage
```
Usage: main.rb [options]
    -c, --[no-]churn                 Calculate churn (this takes awhile), defaults to off
    -1, --first=TAG                  Set first tag, defaults to 2.0.1
    -2, --second=TAG                 Set second tag, defaults to 2.2.0
    -3, --third=TAG                  Set third tag, defaults to 2.4.0
    -r, --repo_location=LOC          Set the repo location, defaults to ../httpd
    -b, --bug_data_location=LOC      Set the bug data location, defaults to ./data/bugs-2016-04-20.csv
    -g, --gnats_data_location=LOC    Set the old bug data location, defaults to ./data/gnats_archive
    -v, --cve_data_location=LOC      Set the cve data location, defaults to ./data/HTTPD Vulnerabilities - CVEs.csv
    -x, --cve_fix_data_location=LOC  Set the cve-to-fix data location, defaults to ./data/HTTPD Vulnerabilities - CVEs to Fixes.csv
    -o, --output=LOC                 Set the output folder, defaults to ./data
    -h, --help                       Prints this help
```

The application outputs a file for each of the three release tags with bug, vulnerability, sloc, and (if enabled) churn data for each file present in the release.
