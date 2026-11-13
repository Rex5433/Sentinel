import json
import pytest
from sentinel.ingest import parse_windows, parse_linux


@pytest.mark.parametrize('code,channel,provider,expected',[
    (4634,'Security','Microsoft-Windows-Security-Auditing','session_close'),
    (4672,'Security','Microsoft-Windows-Security-Auditing','privilege_assigned'),
    (7045,'System','Service Control Manager','service_installed'),
    (7045,'Security','Service Control Manager',None)])
def test_windows_semantic_mappings(code,channel,provider,expected):
    body=json.dumps({'Id':code,'LogName':channel,'ProviderName':provider,'TargetUserName':'target','SubjectUserName':'subject','ServiceName':'demo'})
    event=parse_windows(body.encode(),file_format='json',source_file='test.json',upload_id='test').events[0]
    assert event.event_type==expected
    if code==4634: assert event.actor=='target'
    if code==4672: assert event.event_type!='sudo_command'


@pytest.mark.parametrize('emitter,message,expected',[
    ('useradd','new user: name=demo, UID=1500','account_created'),
    ('useradd','new user: name=demo, UID=1500, GID=1500','account_created'),
    ('systemd-logind','Removed session c12.','session_close'),
    ('unrelated','new user: name=demo, UID=1500',None),
    ('useradd','quoted new user: name=demo, UID=1500',None)])
def test_linux_source_bound_mappings(emitter,message,expected):
    body=f'2026-11-04T12:00:00Z host {emitter}[123]: {message}\n'.encode()
    event=parse_linux(body,file_format='text',source_file='test.log',upload_id='test').events[0]
    assert event.event_type==expected
    if expected=='account_created': assert event.actor is None and event.target=='demo'
