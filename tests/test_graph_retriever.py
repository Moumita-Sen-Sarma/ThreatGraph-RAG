from threatgraph.retrieval.graph import GraphRetriever


class FakeRecord:
    """
    Mimics a Neo4j Record object.
    """

    def __init__(self, data: dict):
        self._data = data

    def data(self) -> dict:
        return self._data


class FakeDriver:
    """
    Mimics the small part of the Neo4j driver
    that GraphRetriever uses.
    """

    def __init__(self, records):
        self.records = records
        self.last_query = None
        self.last_parameters = None

    def execute_query(self, query, **kwargs):
        self.last_query = query
        self.last_parameters = kwargs

        # Neo4j execute_query normally returns:
        # records, summary, keys
        return self.records, None, []


class FakeNeo4jClient:
    """
    Minimal fake replacement for Neo4jClient.
    """

    def __init__(self, records):
        self.driver = FakeDriver(records)
        self.database = "neo4j"


def test_get_group_techniques():
    records = [
        FakeRecord(
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "description": "Credential dumping technique.",
            }
        ),
        FakeRecord(
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "description": "Command execution technique.",
            }
        ),
    ]

    client = FakeNeo4jClient(records)

    retriever = GraphRetriever(client)

    result = retriever.get_group_techniques("APT29")

    assert len(result) == 2

    assert result[0]["technique_id"] == "T1003"

    assert result[0]["technique_name"] == "OS Credential Dumping"

    assert result[1]["technique_id"] == "T1059"

    # Verify that the group name was actually passed
    # to the Neo4j query.
    assert client.driver.last_parameters["group_name"] == "APT29"


def test_get_group_software():
    records = [
        FakeRecord(
            {
                "software_name": "Mimikatz",
                "description": "Credential access software.",
            }
        )
    ]

    client = FakeNeo4jClient(records)

    retriever = GraphRetriever(client)

    result = retriever.get_group_software("APT29")

    assert len(result) == 1

    assert result[0]["software_name"] == "Mimikatz"

    assert client.driver.last_parameters["group_name"] == "APT29"


def test_get_technique_mitigations():
    records = [
        FakeRecord(
            {
                "mitigation_id": "M1027",
                "mitigation_name": "Password Policies",
                "description": "Example mitigation.",
            }
        )
    ]

    client = FakeNeo4jClient(records)

    retriever = GraphRetriever(client)

    result = retriever.get_technique_mitigations("T1003")

    assert len(result) == 1

    assert result[0]["mitigation_id"] == "M1027"

    assert result[0]["mitigation_name"] == "Password Policies"

    assert (
        client.driver.last_parameters["technique_id"]
        == "T1003"
    )


def test_get_group_software_techniques():
    records = [
        FakeRecord(
            {
                "software_name": "Mimikatz",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
            }
        )
    ]

    client = FakeNeo4jClient(records)

    retriever = GraphRetriever(client)

    result = retriever.get_group_software_techniques(
        "APT29"
    )

    assert len(result) == 1

    assert result[0]["software_name"] == "Mimikatz"

    assert result[0]["technique_id"] == "T1003"

    assert (
        result[0]["technique_name"]
        == "OS Credential Dumping"
    )


def test_find_entity():
    records = [
        FakeRecord(
            {
                "labels": [
                    "CTIEntity",
                    "AttackTechnique",
                ],
                "stix_id": "attack-pattern--123",
                "name": "OS Credential Dumping",
            }
        )
    ]

    client = FakeNeo4jClient(records)

    retriever = GraphRetriever(client)

    result = retriever.find_entity(
        "credential dumping"
    )

    assert len(result) == 1

    assert (
        result[0]["name"]
        == "OS Credential Dumping"
    )

    assert (
        client.driver.last_parameters["value"]
        == "credential dumping"
    )