import uuid
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union

from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import select, String

from db.base import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)

class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    def __init__(self, model: Type[ModelType]):
        """
        CRUD object with default methods to Create, Read, Update, Delete (CRUD).
        :param model: A SQLAlchemy model class
        """
        self.model = model

    def get(self, db: Session, id: Any) -> Optional[ModelType]:
        result = db.execute(select(self.model).filter(self.model.id == id))
        return result.scalars().first()

    def get_multi(self, db: Session, *, skip: int = 0, limit: int = 100) -> List[ModelType]:
        result = db.execute(select(self.model).offset(skip).limit(limit))
        return result.scalars().all()

    def create(self, db: Session, *, obj_in: CreateSchemaType, owner_id: Optional[int] = None) -> ModelType:
        # Convert Pydantic model to dict
        obj_in_data = obj_in.dict() if hasattr(obj_in, "dict") else obj_in
        # Add owner_id if provided
        if owner_id is not None:
            obj_in_data["owner_id"] = owner_id
        # Sprawdzenie, czy pole 'id' istnieje i jest typu String
        if hasattr(self.model, "id") and isinstance(getattr(self.model, "id").type, String):
            # Jeśli 'id' nie jest podane w danych wejściowych, generuj UUID
            if "id" not in obj_in_data or obj_in_data["id"] is None:
                obj_in_data["id"] = str(uuid.uuid4())
        # Create SQLAlchemy model instance
        db_obj = self.model(**obj_in_data)
        db_obj.id = str(uuid.uuid4())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(self, db: Session, *, db_obj: ModelType, obj_in: Union[UpdateSchemaType, Dict[str, Any]]) -> ModelType:
        obj_data = jsonable_encoder(db_obj)
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.dict(exclude_unset=True)
        for field in obj_data:
            if field in update_data:
                setattr(db_obj, field, update_data[field])
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def remove(self, db: Session, *, id: int) -> Optional[ModelType]:
        obj = db.get(self.model, id)
        if obj:
            db.delete(obj)
            db.commit()
        return obj