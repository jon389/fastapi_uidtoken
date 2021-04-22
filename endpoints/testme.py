from endpoints import router


@router.get('/test')
async def testme():
    return {'this': 100}