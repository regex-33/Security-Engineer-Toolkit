# coding: utf8
import unittest
from unittest import TestCase
import urlparse3


class TestUrlParse(TestCase):
    """Test for urlparse3 module"""
    def test_parse_url(self):
        """Test parsing url"""
        url = 'http://yandex.ru/mail/?id=123#anchor'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(parsed_url.scheme, 'http')
        self.assertEqual(parsed_url.domain, 'yandex.ru')
        self.assertEqual(parsed_url.path, '/mail/')
        self.assertEqual(parsed_url.query, {'id': '123'})
        self.assertEqual(parsed_url.fragment, 'anchor')
        url = 'http://yandex.ru/mail/?id=123&id=321&id=43#anchor'
        parsed_url = urlparse3.parse_url(url)
        self.assertIsNotNone(parsed_url.query.get('id'))
        for i in parsed_url.query['id']:
            if i not in ['123', '321', '43']:
                self.assertIn(i, ['123', '321', '43'])
        url = 'http://google.com/path/'
        parsed_url = urlparse3.parse_url(url)
        parsed_url.query['cardNumber'] = '12345678910'
        self.assertEqual(parsed_url.geturl(),
                         'http://google.com/path/?cardNumber=12345678910')
                         
    def def_parsed_3d_level_domain(self):
        """Test parse 3rd level domain domain"""
        url = 'http://domain.com.ru/?id=123'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(parsed_url.domain, 'domain.com.ru')
        self.assertEqual(parsed_url.query, {'id': '123'})

    def test_parse_http_auth_url(self):
        """Test parse url with username and password (http basic auth)"""
        url = 'http://admin:password@domain.com/path/?id=123#anchor'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(parsed_url.username, 'admin')
        self.assertEqual(parsed_url.password, 'password')
        self.assertEqual(parsed_url.domain, 'domain.com')
        self.assertEqual(parsed_url.path, '/path/')
        self.assertEqual(parsed_url.query, {'id': '123'})
        self.assertEqual(parsed_url.fragment, 'anchor')
        self.assertEqual(parsed_url.geturl(), url)
        
    def test_parse_semicolo_url(self):
        url = 'http://google.com/?name=alex;id=321'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(parsed_url.query['name'], 'alex')
        self.assertEqual(parsed_url.query['id'], '321')
                
    def test_join_url(self):
        """Test parse url, add new values to 'query' and join url back"""
        url = 'http://yandex.ru/mail/?id=123#anchor'
        parsed_url = urlparse3.parse_url(url)
        parsed_url.query['name'] = 'alex'
        self.assertEqual('http://yandex.ru/mail/?id=123&name=alex#anchor',
                         parsed_url.geturl())
        parsed_url.fragment = 'fragment'
        self.assertEqual('http://yandex.ru/mail/?id=123&name=alex#fragment',
                         parsed_url.geturl())
        url = 'http://yandex.ru/path/?id=1&id=2&id=3&name=alex#anchor'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(len(set(parsed_url.query['id'])), 3, 
                         'Missing parameters in query')
        for i in parsed_url.query['id']:
            self.assertIn(i, ['1', '2', '3'])
        parsed_url.query['id'] = ['1', '2']
        self.assertEqual('http://yandex.ru/path/?id=1&id=2&name=alex#anchor',
                         parsed_url.geturl())
                         
        url = 'http://yandex.ru'
        parsed_url = urlparse3.parse_url(url)
        parsed_url.path = 'search'
        self.assertEqual('http://yandex.ru/search', 
                         parsed_url.geturl())
        
        url = 'http://yandex.ru'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual('http://yandex.ru/', 
                         parsed_url.geturl())

    def test_parse_url_with_port(self):
        url = 'http://localhost:8000/news/1/'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(url, parsed_url.geturl())

    def test_parse_url_with_dash(self):
        url = 'http://local-domain.sub-domain.ru:8000/news/1/'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(url, parsed_url.geturl())

    def test_url_with_absolute_url_in_query_param(self):
        url = 'http://yandex.ru/sub/?dir=http://google.com/'
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(url, parsed_url.geturl())

    def test_parse_query_with_abs_path(self):
        location_query = 'http%3A%2F%2Fwww.google.ru%2Fc%2F922%2Fsubdir-one-two%2F%3Fsitelink%3DtopmenuW%26l%3D8' 
        url = 'https://domain.com/subdirectory/?location={0}'.format(location_query)
        parsed_url = urlparse3.parse_url(url)
        self.assertEqual(parsed_url.query['location'], location_query)
        self.assertEqual(url, parsed_url.geturl())

    def test_query_parameters_order(self):
        """
        Test that query parameters retain the order
        in which they were added.
        """
        url = 'http://domain.com/subdir/?url=http://google.com'
        parsed_url = urlparse3.parse_url(url)
        sort_action = 'sort'
        price_order = 'price'
        parsed_url.query['action'] = sort_action
        parsed_url.query['order'] = price_order
        new_url = parsed_url.geturl()
        self.assertEqual('{0}&action={1}&order={2}'.format(
            url, sort_action, price_order), new_url)

    def test_rearrage_parameters_order(self):
        """
        Test that query parameters retain new order
        after rearrange.
        """
        base_url = 'http://domain.com/subdir/'
        url = '{0}?url=http://google.com'.format(base_url)
        parsed_url = urlparse3.parse_url(url)
        url_parameter = parsed_url.query.pop('url')
        sort_action = 'sort'
        price_order = 'price'
        parsed_url.query['action'] = sort_action
        parsed_url.query['order'] = price_order
        parsed_url.query['url'] = url_parameter
        new_url = parsed_url.geturl()
        self.assertEqual('{0}?action={1}&order={2}&url={3}'.format(
            base_url, sort_action, price_order, url_parameter),
            new_url)
        


if __name__ == '__main__':
    unittest.main()        
