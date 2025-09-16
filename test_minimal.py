#!/usr/bin/env python3
import asyncio
import aiohttp

async def test_fetch():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://example.com', timeout=10) as response:
                content = await response.text()
                print(f"Success: Got {len(content)} characters")
                return content
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
        return None

if __name__ == '__main__':
    result = asyncio.run(test_fetch())
    print("Test completed")
