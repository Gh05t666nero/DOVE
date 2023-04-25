# DOVE - Direct Object Vulnerability Evaluator
DOVE is a Python tool for evaluating Insecure Direct Object References vulnerabilities in web applications. It is capable of identifying vulnerabilities caused by the use of direct object references. DOVE uses asyncio and aiohttp libraries to scan URLs in parallel and find vulnerabilities that can be exploited by an attacker.

## Installation
DOVE requires Python 3.6 or above to run. Install the required packages using the following command:
```
pip install -r requirements.txt
```

## Usage
To use DOVE, execute the **dove.py** file and provide the following arguments:
```
python my_script.py -u <login_url> -u1 <username1> -p1 <password1> -u2 <username2> -p2 <password2> -r <max_redirects> -t <max_timeout>
```
| Argument      | Description                                                         |
|---------------|---------------------------------------------------------------------|
| login_url     | The URL of the login page.                                          |
| username1     | The username for the first account.                                 |
| password1     | The password for the first account.                                 |
| username2     | The username for the second account.                                |
| password2     | The password for the second account.                                |
| max_redirects | The maximum number of redirects to follow (default is 10).          |
| max_timeout   | The maximum time in seconds to wait for a response (default is 10). |

DOVE will then scan the application for direct object vulnerabilities and report any potential issues. The tool uses a combination of techniques to identify direct object vulnerabilities. It checks if the URL contains an ID and if the same ID is used in other URLs. It also checks if the URL contains query parameters and if these parameters can be exploited by an attacker.

DOVE is capable of comparing the content of two URLs to identify any differences that may indicate a vulnerability. It calculates the number of differences between the two URLs and determines if they are within a specified tolerance range. If the differences are within the tolerance range or if the URLs contain the same ID or query parameters, DOVE reports the URL as vulnerable.

DOVE is a fast and efficient tool that can scan multiple URLs in parallel. It uses asyncio and aiohttp to scan URLs asynchronously, which makes it faster than traditional scanning tools that use a sequential approach.

## Contributing
Contributions are welcome! If you have any suggestions or find any bugs, please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the **LICENSE** file for details.
