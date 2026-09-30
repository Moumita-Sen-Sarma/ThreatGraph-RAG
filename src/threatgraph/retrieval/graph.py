from __future__ import annotations

from threatgraph.graph.client import Neo4jClient


class GraphRetriever:
    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    def get_group_techniques(
        self,
        group_name: str,
    ) -> list[dict]:
        """
        Return ATT&CK techniques directly used by a threat group.
        """
        query = """
        MATCH (g:ThreatGroup)-[:USES]->(t:AttackTechnique)
        WHERE toLower(g.name) = toLower($group_name)
        RETURN
            t.external_id AS technique_id,
            t.name AS technique_name,
            t.description AS description
        ORDER BY t.external_id
        """

        records, _, _ = self.client.driver.execute_query(
            query,
            group_name=group_name,
            database_=self.client.database,
        )

        return [record.data() for record in records]

    def get_group_software(
        self,
        group_name: str,
    ) -> list[dict]:
        """
        Return software directly used by a threat group.
        """
        query = """
        MATCH (g:ThreatGroup)-[:USES]->(s:Software)
        WHERE toLower(g.name) = toLower($group_name)
        RETURN
            s.name AS software_name,
            s.description AS description
        ORDER BY s.name
        """

        records, _, _ = self.client.driver.execute_query(
            query,
            group_name=group_name,
            database_=self.client.database,
        )

        return [record.data() for record in records]

    def get_technique_mitigations(
        self,
        technique_id: str,
    ) -> list[dict]:
        """
        Return mitigations connected to an ATT&CK technique.
        """
        query = """
        MATCH (m:Mitigation)-[:MITIGATES]->(t:AttackTechnique)
        WHERE toLower(t.external_id) = toLower($technique_id)
        RETURN
            m.external_id AS mitigation_id,
            m.name AS mitigation_name,
            m.description AS description
        ORDER BY m.external_id
        """

        records, _, _ = self.client.driver.execute_query(
            query,
            technique_id=technique_id,
            database_=self.client.database,
        )

        return [record.data() for record in records]

    def get_group_software_techniques(
        self,
        group_name: str,
    ) -> list[dict]:
        """
        Multi-hop query:
        ThreatGroup -> Software -> AttackTechnique
        """
        query = """
        MATCH
            (g:ThreatGroup)-[:USES]->(s:Software)
            -[:USES]->(t:AttackTechnique)
        WHERE toLower(g.name) = toLower($group_name)
        RETURN DISTINCT
            s.name AS software_name,
            t.external_id AS technique_id,
            t.name AS technique_name
        ORDER BY s.name, t.external_id
        """

        records, _, _ = self.client.driver.execute_query(
            query,
            group_name=group_name,
            database_=self.client.database,
        )

        return [record.data() for record in records]

    def find_entity(
    self,
    name: str,
) -> list[dict]:
        """
        Search CTI entities by name.
        """
        query = """
        MATCH (n:CTIEntity)
        WHERE toLower(n.name) CONTAINS toLower($name)
        RETURN
            labels(n) AS labels,
            n.stix_id AS stix_id,
            n.name AS name
        ORDER BY n.name
        LIMIT 20
        """

        records, _, _ = self.client.driver.execute_query(
            query,
            name=name,
            database_=self.client.database,
        )

        return [record.data() for record in records]