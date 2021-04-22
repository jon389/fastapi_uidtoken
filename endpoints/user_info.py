from endpoints import router, Depends
from internal.auth import User, get_current_active_user


@router.get('/me', response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


# @app.get('/users/me/items/')
# async def read_own_items(current_user: User = Depends(get_current_active_user)):
#     return [{'item_id': 'Foo', 'owner': current_user.username}]
