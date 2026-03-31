from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class NodeType(str, Enum):
    USER = "USER"
    ROLE = "ROLE"
    GROUP = "GROUP"
    COMPUTE = "COMPUTE"
    STORAGE = "STORAGE"

class Identity(BaseModel):
    id: str = Field(description="Unique identifier (e.g., ARN in AWS)")
    name: str = Field(description="Friendly name")
    type: NodeType = Field(description="Type of identity")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw metadata from AWS")
    policies: List[Dict[str, Any]] = Field(default_factory=list, description="Attached policies")
    group_policies: List[Dict[str, Any]] = Field(default_factory=list, description="Policies inherited from groups")
    permissions_boundary: Optional[Dict[str, Any]] = Field(default=None, description="Permissions boundary policy")
    scps: List[Dict[str, Any]] = Field(default_factory=list, description="Service Control Policies")

class Resource(BaseModel):
    id: str = Field(description="Unique identifier (e.g., ARN in AWS)")
    name: str = Field(description="Friendly name")
    type: NodeType = Field(description="Type of resource")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw metadata from AWS")
    policies: List[Dict[str, Any]] = Field(default_factory=list, description="Resource-based policies if applicable")
