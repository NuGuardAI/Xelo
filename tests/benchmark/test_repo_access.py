#!/usr/bin/env python3
"""Test script to check private repo access and langchain-quickstart issues."""
import os
from dotenv import load_dotenv
load_dotenv('../.env')

import httpx  # noqa: E402

token = os.getenv('GITHUB_TOKEN')
print(f'Token available: {bool(token)} ({len(token) if token else 0} chars)')

headers = {'Authorization': f'token {token}'} if token else {}

# Test voicelive repo access
print('\n=== Testing voicelive-api-salescoach-demo ===')
resp = httpx.get('https://api.github.com/repos/NuGuardAI/voicelive-api-salescoach-demo', headers=headers)
print(f'Status: {resp.status_code}')
if resp.status_code == 200:
    data = resp.json()
    print(f"Name: {data.get('name')}")
    print(f"Private: {data.get('private')}")
    print(f"Default branch: {data.get('default_branch')}")
    
    # Get tree
    branch = data.get('default_branch', 'main')
    tree_resp = httpx.get(
        f"https://api.github.com/repos/NuGuardAI/voicelive-api-salescoach-demo/git/trees/{branch}?recursive=1",
        headers=headers
    )
    print(f"Tree status: {tree_resp.status_code}")
    if tree_resp.status_code == 200:
        tree = tree_resp.json()
        files = [f['path'] for f in tree.get('tree', []) if f['type'] == 'blob']
        print(f"Files found: {len(files)}")
        for f in files[:10]:
            print(f"  - {f}")
else:
    print(f"Error: {resp.text}")

# Test langchain repo access with subfolder
print('\n=== Testing langchain-quickstart (langchain-ai/langchain) ===')
resp = httpx.get('https://api.github.com/repos/langchain-ai/langchain', headers=headers)
print(f'Status: {resp.status_code}')
if resp.status_code == 200:
    data = resp.json()
    print(f"Default branch: {data.get('default_branch')}")
    
    # Get specific commit tree
    commit_sha = '273d282a298a45d839cdde7dc13e7ea545c4e1f6'
    tree_resp = httpx.get(
        f"https://api.github.com/repos/langchain-ai/langchain/git/trees/{commit_sha}?recursive=1",
        headers=headers
    )
    print(f"Tree status: {tree_resp.status_code}")
    if tree_resp.status_code == 200:
        tree = tree_resp.json()
        all_files = [f['path'] for f in tree.get('tree', []) if f['type'] == 'blob']
        print(f"Total files: {len(all_files)}")
        
        # Filter to docs/docs/tutorials subfolder
        tutorial_files = [f for f in all_files if f.startswith('docs/docs/tutorials/')]
        print(f"Tutorial files: {len(tutorial_files)}")
        for f in tutorial_files[:10]:
            print(f"  - {f}")
    else:
        print(f"Tree error: {tree_resp.text[:200]}")
