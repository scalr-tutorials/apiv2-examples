<?php

class ScalrAPI
{
	function __construct($url, $key_id, $key_secret)
	{
		//Contains last errors
		$this->errors = '';
		
		$this->api_url = $url;
		$this->api_key_id = $key_id;
		$this->api_key_secret = $key_secret;

		date_default_timezone_set('UTC');
	}

	//Makes the raw request to the API
	private function request($method, $url, $body='')
	{
		//JSON encode body if set
		if ($body) $body = json_encode($body);
		
		//Split URL into components
		$parts = parse_url($url);
		
		$uri = $parts['path'];

		$query = '';
		if (isset($parts['query']))
		{
			//Convert querystring into an array
			parse_str($parts['query'], $query);
			
			//Sort the querystring array
			ksort($query);

			//Convert querystring array back to a string
			$query = http_build_query($query);
		}
		
		//Create ISO 8601 date/time string
		$time = date('c');
		
		//Collection of request data for generating signature
		$request = array
		(
			$method,
			$time,
			$uri,
			$query,
			$body
		);
		
		//Calculate signature based on request data
		$signature = 'V1-HMAC-SHA256 ' . base64_encode(hash_hmac('sha256', implode("\n", $request), $this->api_key_secret, true));
				
		//HTTP request headers
		$headers = array();
		$headers[] = "X-Scalr-Key-Id: {$this->api_key_id}";
		$headers[] = "X-Scalr-Signature: $signature";
		$headers[] = "X-Scalr-Date: $time";
		
		if ($body) $headers[] = 'Content-Type: application/json';
		
		//Make HTTP request to API
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, "{$this->api_url}$uri?$query");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
		
		if ($body) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
	
		$response = curl_exec($ch);
		
		$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

		$response = json_decode($response);
		$error = null;
		
		if ($status >= 400 || $status == 0 || isset($response->errors)) 
		{
			if ($status == 0) {
				$error = curl_error($ch);
			} else {
				$error = isset($response->errors) ? $response->errors[0]->message : $status;	
			}
		}
		
		if ($error) 
		{
			curl_close($ch);
			$this->errors = $error;
			throw new Exception($error);
		}
		
		return $response;
	}
	
	//List items from API
	public function scroll($url)
	{
		$data = array();
		while ($url)
		{
			$response = $this->request('GET', $url);
			$data = array_merge($data, $response->data);
			$url = $response->pagination->next;
		}
		
		return $data;
	}
	
	//Fetch a single item from API
	public function fetch($url)
	{
		$response = $this->request('GET', $url);
		return $response->data;
	}
	
	//Create item in API
	public function create($url, $data)
	{
		$response = $this->request('POST', $url, $data);
		return $response->data;
	}
	
	//Delete item from API
	public function delete($url)
	{
		$response = $this->request('DELETE', $url);
		if ($response) return true;
		return false;
	}
	
	//Edit items in API
	public function edit($url, $data)
	{
		$response = $this->request('PATCH', $url, $data);
		return $response->data;
	}
	
}
