from fastapi import APIRouter
from utils.get_system_info import get_system_info

router = APIRouter()


@router.get("/system_info")
def system_status():
    return get_system_info()
