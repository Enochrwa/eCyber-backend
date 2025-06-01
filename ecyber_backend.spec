# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(
    ['main.py'],
    pathex=['.'],  # Assuming this spec file is in the backend directory
    binaries=[],
    datas=[
        ('ml/models', 'ml/models'),
        ('rules.json', '.'),
        ('threat_feeds_cache.json', '.') # Added as it's loaded by path in ips/engine.py
    ],
    hiddenimports=[
        'uvicorn',
        'fastapi',
        'pydantic',
        'starlette',
        'sqlalchemy',
        'sqlalchemy.ext.asyncio',
        'sqlalchemy.dialects.sqlite', # Assuming SQLite, add others if used e.g. psycopg2cffi
        'joblib',
        'sklearn',
        'sklearn.utils._typedefs',
        'sklearn.neighbors._tree',
        'sklearn.tree',
        'sklearn.tree._utils',
        'sklearn.ensemble',
        'sklearn.ensemble._forest',
        'numpy',
        'scipy',
        'scipy.special',
        'scipy.linalg',
        'scipy.integrate',
        'pandas',
        'logging.handlers', # For RotatingFileHandler
        'asyncio',
        'socketio',
        'aiohttp',
        'aioredis',
        'psutil',
        'passlib',
        'aiosqlite',
        'passlib.handlers.bcrypt',
        'passlib.handlers',
        'jose',
        'bcrypt', # backend by passlib
        'dotenv', # for python-dotenv
        'dns', # for dnspython
        'whois', # for python-whois
        'Levenshtein', # for python-Levenshtein
        'tldextract',
        'certifi', # for SSL contexts
        'scapy',
        'scapy.layers.inet',
        'scapy.layers.l2',
        'scapy.layers.http',
        'scapy.layers.dns',
        'scapy.layers.inet6',
        # Add any other specific scapy layers if needed
        'app.core.config', # If settings are accessed in a way PyInstaller misses
        'app.database',
        'app.models',
        'app.schemas',
        'app.services',
        'app.api',
        'app.utils',
        'ml.feature_extraction',
        # For Hypercorn/FastAPI workers
        'hypercorn',
        'hypercorn.config',
        'hypercorn.middleware',
        'hypercorn.asyncio',
        'hypercorn.trio',  # include if you ever use trio mode
        'hypercorn.protocol',
        'hypercorn.protocol.h11_impl',
        'hypercorn.protocol.h2_impl',
        'hypercorn.protocol.quic_impl',
        'hypercorn.protocol.wsgi_impl',

    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ecyber_backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True, # Set to False if UPX is not available or causes issues
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True, # True for backend services, False for GUI apps
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ecyber_backend_dist' # Output folder name
)
