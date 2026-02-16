from typing import Union, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field

class EmailPasswordModel(BaseModel):
    """
    Model for validating email and password.
    """
    email: EmailStr
    password: str = Field(..., min_length=6)

class RequestBody(BaseModel):
    """
    Model for request body. Can be a single object or a list of objects.
    """
    data: Union[Dict[str, Any], List[Dict[str, Any]]]
