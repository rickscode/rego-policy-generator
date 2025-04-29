import streamlit as st
import os
from groq import Groq
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Initialize Groq client
client = Groq(api_key=GROQ_API_KEY)

# Available LLM models
MODEL_OPTIONS = [
    "llama3-8b-8192",
    "llama3-70b-8192",
    "deepseek-r1-distill-llama-70b"
]

# Few-shot REGO examples
few_shot_examples = """
Example 1:
Policy Description:
Allow access to users with the role "admin".

REGO Policy:
package authz

default allow = false

allow {
    input.role == "admin"
}

---

Example 2:
Policy Description:
Deny all IP addresses not in the allowed list.

REGO Policy:
package network

default allow = false

allow {
    input.ip == "192.168.1.1"
} {
    input.ip == "10.0.0.2"
}

---

Example 3:
Policy Description:
Approve requests only if the request time is between 9AM and 5PM.

REGO Policy:
package timebased

default allow = false

allow {
    input.time >= 9
    input.time <= 17
}
"""

# Streamlit UI
st.title("🛡️ REGO Policy Generator")

with st.sidebar:
    selected_model = st.selectbox("Choose a Model", MODEL_OPTIONS)
    st.markdown("---")
    st.write("This app generates REGO policies based on your description.")

# User input
user_prompt = st.text_area("Describe the policy you want:", height=200)

if st.button("Generate REGO"):
    if not user_prompt.strip():
        st.warning("Please enter a policy description.")
    else:
        with st.spinner("Generating REGO Policy..."):

            # Full prompt with few-shot
            full_prompt = f"""
You are a cybersecurity expert specializing in Open Policy Agent (OPA) and REGO policies.

Use the following examples to understand the style and structure.

{few_shot_examples}

Now, based on this new Policy Description, generate a REGO policy.
Only output the REGO code block. No explanation, no extra text.

Policy Description:
\"\"\"
{user_prompt}
\"\"\"
"""

            chat_completion = client.chat.completions.create(
                model=selected_model,
                messages=[
                    {"role": "system", "content": "You are an expert REGO policy writer."},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.2
            )
            output = chat_completion.choices[0].message.content.strip()

        st.subheader("Generated REGO Policy:")
        st.code(output, language="rego")

        st.session_state["generated_rego"] = output

# Allow downloading if generated
if "generated_rego" in st.session_state:
    st.download_button(
        label="Download REGO File",
        data=st.session_state["generated_rego"],
        file_name="generated_policy.rego",
        mime="text/plain"
    )
