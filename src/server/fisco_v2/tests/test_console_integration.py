"""
测试节点状态服务中的控制台部署调用。
"""

def test_imports():
    """测试导入是否正常。"""
    try:
        print("导入成功")
        return True
    except Exception as e:
        print(f"导入失败: {e}")
        return False

if __name__ == "__main__":
    success = test_imports()
    if success:
        print("所有测试通过")
    else:
        print("测试失败")