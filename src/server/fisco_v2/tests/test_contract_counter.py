"""
合约初始化服务的基本测试：
- 仅测试公开接口与纯函数，不触发真实控制台交互。
"""

from src.server.fisco_v2.services.contract_counter import (
    extract_contract_address_from_deploy_log,
    is_counter_initialized,
)


def test_extract_contract_address_from_deploy_log_cases():
    # 情况1：同一行包含 Counter 与地址
    sample1 = (
        "[INFO] deploy -> Counter success. address: 0x1234567890abcdef1234567890ABCDEF12345678"
    )
    addr1 = extract_contract_address_from_deploy_log(sample1)
    assert addr1 == "0x1234567890abcdef1234567890ABCDEF12345678"

    # 情况2：另一种格式
    sample2 = (
        "==== Deploy Log ====\nname: Counter\naddress=0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
    )
    addr2 = extract_contract_address_from_deploy_log(sample2)
    assert addr2 == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"

    # 情况3：文本中多个地址，优先与 Counter 同行
    sample3 = (
        "Some other address 0x0000000000000000000000000000000000000000\n"
        "Counter deployed at 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    addr3 = extract_contract_address_from_deploy_log(sample3)
    assert addr3 == "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    # 情况4：无地址
    sample4 = "no address here"
    addr4 = extract_contract_address_from_deploy_log(sample4)
    assert addr4 is None


def test_is_counter_initialized_returns_bool():
    flag = is_counter_initialized()
    assert isinstance(flag, bool)


