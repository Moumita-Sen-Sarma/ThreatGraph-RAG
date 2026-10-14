from __future__ import annotations

import os

import streamlit as st


# --------------------------------------------------
# 1. Make Streamlit Cloud secrets available
#    as normal environment variables.
# --------------------------------------------------

SECRET_KEYS = [
    "NEO4J_URI",
    "NEO4J_USERNAME",
    "NEO4J_PASSWORD",
    "NEO4J_DATABASE",
    "OPENAI_API_KEY",
]

for key in SECRET_KEYS:

    if key in os.environ:
        continue

    try:
        value = st.secrets.get(key)
    except Exception:
        value = None

    if value:
        os.environ[key] = str(value)


# Import only after environment variables
# have been prepared.
from threatgraph.mcp.server import (
    get_hybrid_rag,
)


# --------------------------------------------------
# 2. Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="ThreatGraph",
    page_icon="🛡️",
    layout="wide",
)


# --------------------------------------------------
# 3. Cache the expensive Hybrid RAG pipeline
# --------------------------------------------------

@st.cache_resource
def load_threatgraph():
    """
    Initialize ThreatGraph once per Streamlit
    server process.
    """

    return get_hybrid_rag()


# --------------------------------------------------
# 4. Header
# --------------------------------------------------

st.title("ThreatGraph: Hybrid RAG for Knowledge-Grounded Cyber Threat Intelligence")

st.caption(
    "Answers cyber threat intelligence questions using Hybrid RAG" 
    "that combines Knowledge Graphs and vector retrieval, with "
    "provenance for traceable, grounded responses."
)


# --------------------------------------------------
# 5. User question
# --------------------------------------------------

question = st.text_area(
    "Ask a cyber threat intelligence question",
    placeholder=(
        "Example: If Cozy Bear performs credential "
        "dumping, what mitigations should we apply?"
    ),
    height=100,
)

top_k = st.slider(
    "Vector evidence to retrieve",
    min_value=1,
    max_value=10,
    value=5,
)


# --------------------------------------------------
# 6. Run ThreatGraph
# --------------------------------------------------

if st.button(
    "Ask ThreatGraph",
    type="primary",
):

    if not question.strip():

        st.warning(
            "Please enter a question."
        )

    else:

        with st.spinner(
            "Searching ThreatGraph..."
        ):

            try:

                rag = load_threatgraph()

                result = rag.answer(
                    question.strip(),
                    top_k=top_k,
                )

            except Exception as exc:

                st.error(
                    "ThreatGraph could not process "
                    "the request."
                )

                st.exception(exc)

                st.stop()


        # ------------------------------------------
        # 7. Main answer
        # ------------------------------------------

        st.subheader("Answer")

        st.markdown(
            result["answer"]
        )


        # ------------------------------------------
        # 8. Grounding status
        # ------------------------------------------

        if (
            result["grounding_status"]
            == "passed"
        ):

            st.success(
                "Grounded answer — citations validated."
            )

        elif (
            result["grounding_status"]
            == "repaired"
        ):

            st.warning(
                "The original answer contained an "
                "invalid citation and was automatically "
                "repaired."
            )

        else:

            st.error(
                "The answer could not be fully grounded."
            )


        # ------------------------------------------
        # 9. Resolution evidence
        # ------------------------------------------

        with st.expander(
            "Entity Resolution",
        ):

            resolution_evidence = (
                result[
                    "resolution_evidence"
                ]
            )

            if not resolution_evidence:

                st.info(
                    "No entity-resolution evidence."
                )

            for item in resolution_evidence:

                evidence_id = (
                    item["evidence_id"]
                )

                data = item["data"]

                st.markdown(
                    f"### {evidence_id}"
                )

                st.write(
                    "Role:",
                    data.get("role"),
                )

                st.write(
                    "Resolved entity:",
                    data.get("name"),
                )

                if data.get("external_id"):

                    st.write(
                        "ATT&CK ID:",
                        data["external_id"],
                    )

                aliases = data.get(
                    "aliases"
                )

                if aliases:

                    st.write(
                        "Aliases:",
                        ", ".join(aliases),
                    )

                st.divider()


        # ------------------------------------------
        # 10. Graph evidence
        # ------------------------------------------

        with st.expander(
            "Graph Evidence",
        ):

            graph_evidence = (
                result["graph_evidence"]
            )

            if not graph_evidence:

                st.info(
                    "No graph evidence retrieved."
                )

            for item in graph_evidence:

                evidence_id = (
                    item["evidence_id"]
                )

                data = item["data"]

                st.markdown(
                    f"### {evidence_id}"
                )

                mitigation_name = (
                    data.get(
                        "mitigation_name"
                    )
                )

                mitigation_id = (
                    data.get(
                        "mitigation_id"
                    )
                )

                if mitigation_name:

                    st.write(
                        "Mitigation:",
                        mitigation_name,
                    )

                if mitigation_id:

                    st.write(
                        "MITRE ID:",
                        mitigation_id,
                    )

                supporting = data.get(
                    "supporting_techniques",
                    [],
                )

                if supporting:

                    st.write(
                        "Supporting techniques:"
                    )

                    for technique in supporting:

                        st.write(
                            "•",
                            technique.get(
                                "technique_id"
                            ),
                            technique.get(
                                "technique_name"
                            ),
                        )

                description = data.get(
                    "mitigation_description"
                )

                if description:

                    st.write(
                        description
                    )

                st.divider()


        # ------------------------------------------
        # 11. Vector evidence
        # ------------------------------------------

        with st.expander(
            "Vector Evidence",
        ):

            vector_evidence = (
                result["vector_evidence"]
            )

            if not vector_evidence:

                st.info(
                    "No vector evidence retrieved."
                )

            for item in vector_evidence:

                evidence_id = (
                    item["evidence_id"]
                )

                document = item["data"]

                st.markdown(
                    f"### {evidence_id} — "
                    f"{document.get('title', '')}"
                )

                st.write(
                    "Source:",
                    document.get("source"),
                )

                score = document.get(
                    "score"
                )

                if score is not None:

                    st.write(
                        "Similarity:",
                        f"{score:.4f}",
                    )

                st.write(
                    document.get(
                        "text",
                        ""
                    )
                )

                st.divider()


        # ------------------------------------------
        # 12. Advanced diagnostics
        # ------------------------------------------

        with st.expander(
            "Advanced Details",
        ):

            st.write(
                "Route:",
                result["route"],
            )

            st.write(
                "Citation validation:",
                result[
                    "citation_validation"
                ],
            )

            st.write(
                "Repair attempted:",
                result[
                    "repair_attempted"
                ],
            )