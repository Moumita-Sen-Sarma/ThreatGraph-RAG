from threatgraph.graph.client import Neo4jClient
from threatgraph.models.schema import (
    AttackTechnique,
    Campaign,
    Mitigation,
    Software,
    ThreatGroup,
)


class GraphBuilder:
    def __init__(self, client: Neo4jClient) -> None:
        self.client = client

    def create_threat_group(
        self,
        group: ThreatGroup,
    ) -> None:
        query = """
        MERGE (g:ThreatGroup {stix_id: $stix_id})
        SET
            g.name = $name,
            g.description = $description,
            g.aliases = $aliases
        """

        self.client.driver.execute_query(
            query,
            stix_id=group.stix_id,
            name=group.name,
            description=group.description,
            aliases=group.aliases,
            database_=self.client.database,
        )

    def create_attack_technique(
        self,
        technique: AttackTechnique,
    ) -> None:
        query = """
        MERGE (t:AttackTechnique {stix_id: $stix_id})
        SET
            t.external_id = $external_id,
            t.name = $name,
            t.description = $description,
            t.platforms = $platforms
        """

        self.client.driver.execute_query(
            query,
            stix_id=technique.stix_id,
            external_id=technique.external_id,
            name=technique.name,
            description=technique.description,
            platforms=technique.platforms,
            database_=self.client.database,
        )

    def create_software(
        self,
        software: Software,
    ) -> None:
        query = """
        MERGE (s:Software {stix_id: $stix_id})
        SET
            s.name = $name,
            s.description = $description,
            s.aliases = $aliases
        """

        self.client.driver.execute_query(
            query,
            stix_id=software.stix_id,
            name=software.name,
            description=software.description,
            aliases=software.aliases,
            database_=self.client.database,
        )

    def create_mitigation(
        self,
        mitigation: Mitigation,
    ) -> None:
        query = """
        MERGE (m:Mitigation {stix_id: $stix_id})
        SET
            m.external_id = $external_id,
            m.name = $name,
            m.description = $description
        """

        self.client.driver.execute_query(
            query,
            stix_id=mitigation.stix_id,
            external_id=mitigation.external_id,
            name=mitigation.name,
            description=mitigation.description,
            database_=self.client.database,
        )

    def create_campaign(
        self,
        campaign: Campaign,
    ) -> None:
        query = """
        MERGE (c:Campaign {stix_id: $stix_id})
        SET
            c.name = $name,
            c.description = $description,
            c.aliases = $aliases
        """

        self.client.driver.execute_query(
            query,
            stix_id=campaign.stix_id,
            name=campaign.name,
            description=campaign.description,
            aliases=campaign.aliases,
            database_=self.client.database,
        )