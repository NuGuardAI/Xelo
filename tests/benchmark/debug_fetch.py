"""Debug script to test file fetching for benchmark repos."""
import asyncio
import os
from fetcher import fetch_github_tree, parse_github_url, should_fetch_file

async def debug_autogen():
    gt = {
        'repo_url': 'https://github.com/microsoft/autogen',
        'branch': 'main',
        'subfolder': 'python/samples/agentchat_quickstart',
        'commit_sha': '13e144e5476a76ca0d76bf4f07a6401d133a03ed'
    }
    token = os.getenv('GITHUB_TOKEN')
    owner, repo = parse_github_url(gt['repo_url'])
    ref = gt.get('commit_sha') or gt.get('branch', 'main')
    
    print(f'Fetching tree for {owner}/{repo} ref={ref}')
    print(f'Subfolder: {gt.get("subfolder")}')
    
    tree = await fetch_github_tree(owner, repo, ref, token, gt.get('subfolder'))
    print(f'Tree items after subfolder filter: {len(tree)}')
    
    if tree:
        print("First 10 files:")
        for f in tree[:10]:
            should = should_fetch_file(f['path'], f.get('size', 0))
            print(f"  {f['path']} (size={f.get('size', 0)}) -> fetch={should}")
    else:
        # Try without subfolder to see what's in the repo
        print("\nTrying without subfolder filter:")
        tree_all = await fetch_github_tree(owner, repo, ref, token, None)
        print(f'Total tree items: {len(tree_all)}')
        
        # Check for our target path
        target = 'python/samples/agentchat_quickstart'
        matching = [f for f in tree_all if target in f['path']]
        print(f'Files matching "{target}": {len(matching)}')
        for f in matching[:10]:
            print(f"  {f['path']}")
        
        # Search more broadly
        print("\nSearching for 'quickstart' in paths:")
        quick_match = [f for f in tree_all if 'quickstart' in f['path'].lower()][:20]
        for f in quick_match:
            print(f"  {f['path']}")
        
        print("\nSearching for 'agentchat' in paths:")
        agent_match = [f for f in tree_all if 'agentchat' in f['path'].lower()][:20]
        for f in agent_match:
            print(f"  {f['path']}")
        
        print("\nSearching for '.py' files under python/:")
        py_files = [f for f in tree_all if f['path'].startswith('python/') and f['path'].endswith('.py')][:30]
        for f in py_files:
            print(f"  {f['path']}")

if __name__ == '__main__':
    asyncio.run(debug_autogen())
