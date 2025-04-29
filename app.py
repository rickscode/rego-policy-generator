import streamlit as st
import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Initialize Groq client
client = Groq(api_key=GROQ_API_KEY)

# LLM models
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

---

Example 4:
Policy Description:
Complex hierarchical authorization - Allow access if user is either:
1. An admin in any department, OR
2. A manager in the same department as the resource

REGO Policy:
package hierarchical_authz

default allow = false

allow {
    input.user.roles[_] == "admin"
} {
    input.user.roles[_] == "manager"
    input.user.department == input.resource.department
}

---

Example 5:
Policy Description:
Validate JWT tokens with RS256 signature and check claims:
1. Token must be valid and not expired
2. Audience must match our service
3. Must have either "read:data" or "write:data" scope

REGO Policy:
package jwt_authz

import future.keywords.in

default allow = false

allow {
    [valid, _, _] := io.jwt.decode_verify(input.jwt, {
        "cert": input.cert,
        "alg": "RS256"
    })
    valid
    now := time.now_ns() / 1000000000
    payload := io.jwt.decode(input.jwt)[1]
    payload.exp >= now
    payload.aud == "my-service"
    valid_scopes(payload.scope)
}

valid_scopes(scopes) {
    scopes[_] == "read:data"
} {
    scopes[_] == "write:data"
}

---

Example 6:
Policy Description:
Resource quota enforcement with tiered access:
1. Free tier: max 5 resources, each <1GB
2. Pro tier: max 50 resources, each <10GB
3. Enterprise tier: unlimited

REGO Policy:
package quota

import future.keywords.in

default violation = null

violation["Free tier exceeded resource limit"] {
    input.tier == "free"
    count(input.resources) > 5
}

violation["Free tier exceeded size limit"] {
    input.tier == "free"
    resource := input.resources[_]
    resource.size > 1000000000  # 1GB in bytes
}

violation["Pro tier exceeded resource limit"] {
    input.tier == "pro"
    count(input.resources) > 50
}

violation["Pro tier exceeded size limit"] {
    input.tier == "pro"
    resource := input.resources[_]
    resource.size > 10000000000  # 10GB in bytes
}

---

Example 7:
Policy Description:
Complex workflow approval requiring:
1. At least 2 approvers from different teams
2. No conflicts of interest (approver not in same team as requester)
3. Budget under $10k OR CEO approval if over

REGO Policy:
package workflow

import future.keywords.in

default approved = false

approved {
    count(input.approvals) >= 2
    different_team_approvals
    no_conflicts_of_interest
    valid_budget
}

different_team_approvals {
    approver1 := input.approvals[_]
    approver2 := input.approvals[_]
    approver1 != approver2
    approver1.team != approver2.team
}

no_conflicts_of_interest {
    not input.approvals[_].team == input.requester.team
}

valid_budget {
    input.budget <= 10000
} {
    input.budget > 10000
    input.approvals[_].title == "CEO"
}
"""

# Streamlit Dark Theme
st.set_page_config(
    page_title="REGO X: Generate REGO Policies",
    page_icon="🔒",
    layout="wide"
)

# CSS for dark theme 
st.markdown("""
<style>
    [your existing CSS]
</style>
""", unsafe_allow_html=True)

# UI
st.title("🔒 REGO X: Generate REGO Policies")

with st.sidebar:
    st.image("https://openpolicyagent.org/images/opa-logo.svg", width=150)
    selected_model = st.selectbox("Choose a Model", MODEL_OPTIONS)
    st.markdown("---")
    st.write("AI-powered OPA REGO policy generator")
    st.markdown("---")
    st.caption("Tip: Be specific in your policy description for better results")

# User input
col1, col2 = st.columns([3, 1])
with col1:
    user_prompt = st.text_area(
        "Describe the policy you want:",
        height=200,
        placeholder="Example: 'Allow access only to users with admin role from internal IPs during business hours'",
        help="Be as specific as possible about conditions and requirements"
    )

with col2:
    st.markdown("### Examples")
    st.caption("✅ 'Require MFA for all admin access'")
    st.caption("✅ 'Block requests from high-risk countries'")
    st.caption("✅ 'Limit container resources based on team quota'")

if st.button("Generate REGO Policy", type="primary"):
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
Follow these guidelines:
1. Include proper package declaration
2. Set default allow = false when appropriate
3. Use clear, descriptive rule names
4. Include all necessary conditions
5. Format for readability

Only output the REGO code block. No explanation, no extra text.

Policy Description:
\"\"\"
{user_prompt}
\"\"\"
"""

            chat_completion = client.chat.completions.create(
                model=selected_model,
                messages=[
                    {"role": "system", "content": "You are an expert REGO policy writer. Output only valid REGO code."},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.2
            )
            output = chat_completion.choices[0].message.content.strip()

        st.subheader("Generated REGO Policy:")
        
        
        st.code(output, language="rego", line_numbers=True)
        
        st.session_state["generated_rego"] = output
        st.toast("Policy generated successfully!", icon="✅")

        # Policy analysis
        with st.expander("🔍 Policy Analysis"):
            st.markdown("**Key Features:**")
            st.markdown("- Default deny: ✅" if "default allow = false" in output else "- Default deny: ❌")
            st.markdown("- Package declared: ✅" if "package " in output else "- Package declared: ❌")
            st.markdown("- Conditions: " + str(output.count("input.")) + " input checks")

# Download button
if "generated_rego" in st.session_state:
    st.download_button(
        label="⬇️ Download REGO File",
        data=st.session_state["generated_rego"],
        file_name="generated_policy.rego",
        mime="text/plain",
        help="Download the generated REGO policy file"
    )