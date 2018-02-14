import pytest
import docker

test_container_name = 'dosa_docker_test_container'
test_network_name = 'dosa_docker_test_network'


@pytest.fixture
def network():
    """return docker network to use in tests"""
    client = docker.from_env()
    networks = client.networks.list(filters={'type': 'custom'})
    try:
        network = next(
            net for net in networks
            if net.name == test_network_name
            and net.attrs.get('Internal') is True
            and net.attrs.get('Driver') == 'bridge'
            and net.attrs.get('Attachable') is True
        )
    except StopIteration:
        network = client.networks.create(
            name=test_network_name,
            internal=True,
            driver='bridge',
            attachable=True,
        )
    network.reload()
    return network


@pytest.fixture
def container(network):
    """return docker container to use in tests"""
    client = docker.from_env()
    container = client.containers.run(
        'ubuntu', 'sleep infinity',
        name=test_container_name,
        network=network.name,
        remove=True,
        detach=True,
    )
    container.reload()

    yield container

    container.stop(timeout=1)
