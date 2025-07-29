# PITT: The OWASP LLM Top 10 Testing Tool

PITT is a powerful, command-line tool designed to help developers and security professionals assess the security of Large Language Model (LLM) applications. It automates the process of testing for vulnerabilities specific to LLMs, based on the [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

![PITT Demo](DEMO.md)

## Key Features

- **OWASP LLM Top 10 Coverage:** Comes with a pre-built library of tests covering common LLM vulnerabilities like prompt injection, data leakage, and insecure output handling.
- **YAML-Based Test Cases:** Easily create, modify, and extend test cases using a simple YAML format. No complex coding required to add new tests.
- **Intelligent Vulnerability Detection:** PITT goes beyond simple keyword matching. It uses a "Judge LLM" to analyze the responses from the target model, providing more accurate and context-aware vulnerability detection.
- **HTML Reporting:** Generates clear and detailed HTML reports summarizing the test results, making it easy to identify and remediate vulnerabilities.
- **Highly Configurable:** Easily configure the target URL, request parameters, and other settings to match your specific application's API.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/pitt.git
    cd pitt
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

1.  **Copy the example config:**
    ```bash
    cp config.yaml.example config.yaml
    ```

2.  **Edit `config.yaml`:**
    Open `config.yaml` in your favorite editor and configure the following:
    - `target_url`: The API endpoint of your LLM application.
    - `request_method`: The HTTP method to use (e.g., `POST`).
    - `request_body_template`: A template of the request body, with `{payload}` as a placeholder for the test prompt.
    - `judge_llm`: (Recommended) Configure a "Judge LLM" (like Gemini or an OpenAI model) to intelligently analyze test results.

## Usage

- **Run all tests:**
  ```bash
  python3 pitt.py
  ```

- **Run specific tests:**
  ```bash
  python3 pitt.py --rules rule_name_1,rule_name_2
  ```

- **Filter by severity:**
  ```bash
  python3 pitt.py --severity critical,high
  ```

After the tests are complete, a `report.html` file will be generated in the root directory.
And your can check the Example Report file here [report.html](https://github.com/Addy-shetty/Pitt/blob/ec6ab6f668466f15217be8ecb95ea45ddcb4f824/report.html).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to the project.

## License

PITT is released under the [MIT License](LICENSE).
