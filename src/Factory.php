<?php

namespace MailerLite\LaravelElasticsearch;

use Elastic\Elasticsearch\Client;
use Elastic\Elasticsearch\ClientBuilder;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Illuminate\Support\Arr;
use Illuminate\Support\Reflector;
use Psr\Http\Message\RequestInterface;
use Psr\Log\LoggerInterface;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;


class Factory
{
	/**
	 * Make the Elasticsearch client for the given named configuration, or
	 * the default client.
	 *
	 * @param array $config
	 *
	 * @return \Elastic\Elasticsearch\Client
	 */
	public function make(array $config): Client
	{
		return $this->buildClient($config);
	}

	/**
	 * Build and configure an Elasticsearch client.
	 *
	 * @param array $config
	 *
	 * @return \Elastic\Elasticsearch\Client
	 */
	protected function buildClient(array $config): Client
	{
		$clientBuilder = ClientBuilder::create();

		// Configure hosts
		$hosts = $this->buildHosts($config['hosts']);
		$clientBuilder->setHosts($hosts);

		// Configure logging
		if (Arr::get($config, 'logging')) {
			$logObject = Arr::get($config, 'logObject');
			$logPath = Arr::get($config, 'logPath');
			$logLevel = Arr::get($config, 'logLevel');
			if ($logObject && $logObject instanceof LoggerInterface) {
				$clientBuilder->setLogger($logObject);
			} elseif ($logPath && $logLevel) {
				$handler = new StreamHandler($logPath, $logLevel);
				$logObject = new Logger('log');
				$logObject->pushHandler($handler);
				$clientBuilder->setLogger($logObject);
			}
		}

		// Configure retries
		$retries = Arr::get($config, 'retries');
		if ($retries !== null) {
			$clientBuilder->setRetries((int) $retries);
		}

		// Configure SSL verification
		$sslVerification = Arr::get($config, 'sslVerification');
		if ($sslVerification !== null) {
			if (is_string($sslVerification)) {
				$clientBuilder->setCABundle($sslVerification);
			} elseif ($sslVerification === false) {
				$clientBuilder->setSSLVerification(false);
			}
		}

		// Configure basic authentication from the first host
		$firstHost = Arr::first($config['hosts']);
		if (!empty($firstHost['user']) && !empty($firstHost['pass'])) {
			$clientBuilder->setBasicAuthentication($firstHost['user'], $firstHost['pass']);
		}

		// Configure API key authentication
		if (!empty($firstHost['api_key']) && $firstHost['api_key'] !== null) {
			$apiId = $firstHost['api_id'] ?? null;
			if (!empty($apiId)) {
				$clientBuilder->setApiKey($firstHost['api_key'], $apiId);
			} else {
				$clientBuilder->setApiKey($firstHost['api_key']);
			}
		}

		// Configure AWS handler
		$this->configureAwsHandler($clientBuilder, $config);

		// Build and return the client
		return $clientBuilder->build();
	}

	/**
	 * Build host URLs from the configuration arrays.
	 *
	 * @param array $hosts
	 * @return array
	 */
	protected function buildHosts(array $hosts): array
	{
		$builtHosts = [];

		foreach ($hosts as $host) {
			if (is_string($host)) {
				$builtHosts[] = $host;
				continue;
			}

			$scheme = Arr::get($host, 'scheme', 'http');
			$hostname = Arr::get($host, 'host', 'localhost');
			$port = Arr::get($host, 'port');

			$url = $scheme . '://' . $hostname;
			if ($port) {
				$url .= ':' . $port;
			}

			$builtHosts[] = $url;
		}

		return $builtHosts;
	}

	/**
	 * Configure AWS SigV4 signing via a Guzzle middleware if any host has AWS enabled.
	 *
	 * @param ClientBuilder $clientBuilder
	 * @param array $config
	 */
	protected function configureAwsHandler(ClientBuilder $clientBuilder, array $config): void
	{
		foreach ($config['hosts'] as $host) {
			if (isset($host['aws']) && $host['aws']) {
				$stack = HandlerStack::create();

				$stack->push(Middleware::mapRequest(function (RequestInterface $request) use ($host) {
					$signer = new \Aws\Signature\SignatureV4('es', $host['aws_region']);

					$credentials = new \Aws\Credentials\Credentials(
						$host['aws_key'],
						$host['aws_secret'],
						$host['aws_session_token'] ?? null
					);

					if (!empty($host['aws_credentials']) && $host['aws_credentials'] instanceof \Aws\Credentials\Credentials) {
						$credentials = $host['aws_credentials'];
					}

					if (
						!empty($host['aws_credentials'])
						&& is_array($host['aws_credentials'])
						&& Reflector::isCallable($host['aws_credentials'], true)
					) {
						$host['aws_credentials'] = call_user_func([$host['aws_credentials'][0], $host['aws_credentials'][1]]);
					}

					if (!empty($host['aws_credentials']) && $host['aws_credentials'] instanceof \Closure) {
						$credentials = $host['aws_credentials']()->wait();
					}

					return $signer->signRequest($request, $credentials);
				}));

				$guzzleClient = new GuzzleClient(['handler' => $stack]);
				$clientBuilder->setHttpClient($guzzleClient);

				break; // Only one AWS handler needed
			}
		}
	}
}
