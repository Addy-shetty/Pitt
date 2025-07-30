import streamlit as st
import os
import sys
import pandas as pd
import yaml
import asyncio
import ast

# Add the parent directory to the path to allow importing pitt.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from pitt import load_config, load_rules, run_pitt_tests, generate_report # Import necessary functions

st.set_page_config(layout="wide")

def main():
    st.title("Prompt Injection Testing Tool (PITT)")

    st.sidebar.header("Configuration")
    config_file = st.sidebar.file_uploader("Upload config.yaml", type=["yaml", "yml"])
    
    config = {}
    if config_file:
        config = yaml.safe_load(config_file) # Load config from uploaded file
        st.sidebar.success("Config loaded successfully!")
    else:
        st.sidebar.info("Using default config. Upload a file to override.")
        # Provide default config values if no file is uploaded
        config = {
            'target_url': "http://localhost:8080/chat",
            'api_key': "YOUR_API_KEY_HERE",
            'request_method': "POST",
            'request_body_template': {'prompt': '{payload}'},
            'judge_llm': {'enabled': False}
        }

    st.sidebar.subheader("Target Application Settings")
    config['target_url'] = st.sidebar.text_input("Target URL", value=config.get('target_url', "http://localhost:8080/chat"))
    config['api_key'] = st.sidebar.text_input("API Key", value=config.get('api_key', "YOUR_API_KEY_HERE"), type="password")
    config['request_method'] = st.sidebar.selectbox("Request Method", ["POST", "GET"], index=["POST", "GET"].index(config.get('request_method', "POST")))
    
    # Basic request body template input (can be expanded for more complexity)
    request_body_template_str = str(config.get('request_body_template', {'prompt': '{payload}'}))
    request_body_template_input = st.sidebar.text_area("Request Body Template (JSON)", value=request_body_template_str, key='request_body_template_input')
    # Convert string input back to dict
    try:
        config['request_body_template'] = ast.literal_eval(request_body_template_input)
    except Exception as e:
        st.sidebar.error(f"Invalid Request Body Template: {e}")
        return # Stop execution if invalid

    st.sidebar.subheader("Judge LLM Settings")
    judge_llm_enabled = st.sidebar.checkbox("Enable Judge LLM", value=config.get('judge_llm', {}).get('enabled', False))
    if judge_llm_enabled:
        config['judge_llm'] = config.get('judge_llm', {})
        config['judge_llm']['enabled'] = True
        config['judge_llm']['api_key'] = st.sidebar.text_input("Judge LLM API Key", value=config['judge_llm'].get('api_key', "YOUR_JUDGE_LLM_API_KEY_HERE"), type="password")
        config['judge_llm']['model'] = st.sidebar.text_input("Judge LLM Model", value=config['judge_llm'].get('model', "gpt-3.5-turbo"))
        config['judge_llm']['url'] = st.sidebar.text_input("Judge LLM URL", value=config['judge_llm'].get('url', "https://api.openai.com/v1/chat/completions"))
    else:
        if 'judge_llm' in config:
            config['judge_llm']['enabled'] = False


    st.header("Test Settings")
    iterations = st.slider("Number of Iterations per Rule", min_value=1, max_value=10, value=1)

    all_rules = load_rules() # Load all rules initially
    rule_names = [rule['name'] for rule in all_rules]
    selected_rules = st.multiselect("Select Rules to Run", rule_names, default=rule_names)

    severity_options = ["low", "medium", "high"]
    selected_severity = st.multiselect("Filter by Severity", severity_options, default=severity_options)

    firewall_mode = st.checkbox("Enable Firewall Testing Mode")
    pass_condition = None
    if firewall_mode:
        pass_condition = st.text_input("Firewall Pass Condition (expected response string)")
        if not pass_condition:
            st.warning("Please provide a pass condition for Firewall Testing Mode.")

    st.markdown("---")

    if st.button("Run Tests"): # Only run tests when button is clicked
        if firewall_mode and not pass_condition:
            st.error("Cannot run tests: Pass condition is required for Firewall Testing Mode.")
            return

        # Create a dummy args object for run_pitt_tests
        class Args:
            def __init__(self, iterations, rules, severity, firewall, pass_condition):
                self.iterations = iterations
                self.rules = ",".join(rules) if rules else None
                self.severity = ",".join(severity) if severity else None
                self.firewall = firewall
                self.pass_condition = pass_condition

        args = Args(iterations, selected_rules, selected_severity, firewall_mode, pass_condition)

        st.info("Running tests... Please wait.")
        
        # Capture console output (rich output) from pitt.py
        from io import StringIO
        from contextlib import redirect_stdout
        
        f = StringIO()
        with redirect_stdout(f):
            # Run the async function using asyncio.run()
            test_results = asyncio.run(run_pitt_tests(args, config, console_output=False))
        
        output = f.getvalue()
        st.text_area("Console Output", output, height=300)

        if test_results:
            st.subheader("Test Results Summary")
            
            # Prepare data for DataFrame
            df_data = []
            for res in test_results:
                df_data.append({
                    "Name": res['name'],
                    "Type": res['type'],
                    "Severity": res['severity'],
                    "Payload": res['payload'],
                    "Result": "Detected" if res['vulnerable'] else "Not Detected" if firewall_mode else "Vulnerable" if res['vulnerable'] else "Not Vulnerable",
                    "Passed Iterations": res['passed_iterations'],
                    "Total Iterations": res['total_iterations'],
                    "Response (Last Iteration)": res['responses'][-1] if res['responses'] else ""
                })
            
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True)

            # Generate and offer report for download
            results_dict = {res['name']: res for res in test_results}
            generate_report(results_dict, config)
            with open("report.html", "rb") as f_report:
                st.download_button(
                    label="Download HTML Report",
                    data=f_report,
                    file_name="pitt_report.html",
                    mime="text/html"
                )
        else:
            st.warning("No tests were run or no results were generated.")

if __name__ == "__main__":
    main()