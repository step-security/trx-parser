/* eslint-disable i18n-text/no-en */
import * as core from '@actions/core'
import * as fs from 'fs'
import axios, {isAxiosError} from 'axios'

import {getTrxFiles} from './utils/file-utils'
import {transformAllTrxToJson} from './parsers/trx-parser'
import {areThereAnyFailingTests} from './utils/test-analyzer'
import {createCheckRun} from './services/github-service'
import {parseActionInputs} from './validators/input-validator'
import {
  initializeTelemetry,
  shutdownTelemetry,
  withSpan,
  recordActionOutcome,
  recordTestResults,
  recordTrxFileProcessing
} from './services/telemetry-service'

async function validateSubscription(): Promise<void> {
  const eventPath = process.env.GITHUB_EVENT_PATH
  let repoPrivate: boolean | undefined

  if (eventPath && fs.existsSync(eventPath)) {
    const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'))
    repoPrivate = eventData?.repository?.private
  }

  const upstream = 'NasAmin/trx-parser'
  const action = process.env.GITHUB_ACTION_REPOSITORY
  const docsUrl =
    'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions'

  core.info('')
  core.info('\u001b[1;36mStepSecurity Maintained Action\u001b[0m')
  core.info(`Secure drop-in replacement for ${upstream}`)
  if (repoPrivate === false)
    core.info('\u001b[32m\u2713 Free for public repositories\u001b[0m')
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`)
  core.info('')

  if (repoPrivate === false) return

  const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com'
  const body: Record<string, string> = {action: action || ''}
  if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body,
      {timeout: 3000}
    )
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(
        `\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m`
      )
      core.error(
        `\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`
      )
      process.exit(1)
    }
    core.info('Timeout or API not reachable. Continuing to next step.')
  }
}

export async function run(): Promise<void> {
  await validateSubscription()

  // Initialize telemetry first
  const telemetryEnabled = initializeTelemetry()

  try {
    await withSpan(
      'trx_parser_action_run',
      async () => {
        const inputs = parseActionInputs()

        core.info(`Finding Trx files in: ${inputs.trxPath}`)
        const trxFiles = await withSpan(
          'find_trx_files',
          async () => {
            return getTrxFiles(inputs.trxPath)
          },
          {
            trx_path: inputs.trxPath
          }
        )

        core.info(`Processing ${trxFiles.length} trx files`)
        recordTrxFileProcessing(trxFiles.length)

        const trxToJson = await withSpan(
          'transform_trx_files',
          async () => {
            return transformAllTrxToJson(trxFiles)
          },
          {
            file_count: trxFiles.length
          }
        )

        core.info(`Checking for failing tests`)
        const failingTestsFound = areThereAnyFailingTests(trxToJson)

        // Calculate test metrics
        let totalTests = 0
        let passedTests = 0
        let failedTests = 0

        for (const data of trxToJson) {
          if (!data.IsEmpty && data.TrxData.TestRun?.ResultSummary?.Counters) {
            totalTests += data.TrxData.TestRun.ResultSummary.Counters._total
            passedTests += data.TrxData.TestRun.ResultSummary.Counters._passed
            failedTests += data.TrxData.TestRun.ResultSummary.Counters._failed
          }
        }

        recordTestResults(totalTests, passedTests, failedTests)

        // Process check runs in parallel for better performance
        await withSpan(
          'create_check_runs',
          async () => {
            await Promise.all(
              trxToJson.map(async data =>
                withSpan(
                  'create_single_check_run',
                  async () => {
                    return createCheckRun(
                      inputs.token,
                      inputs.ignoreTestFailures,
                      data,
                      inputs.sha,
                      inputs.reportPrefix
                    )
                  },
                  {
                    report_name: data.ReportMetaData.ReportName,
                    total_tests: data.IsEmpty
                      ? 0
                      : data.TrxData.TestRun?.ResultSummary?.Counters?._total ||
                        0,
                    failed_tests: data.IsEmpty
                      ? 0
                      : data.TrxData.TestRun?.ResultSummary?.Counters
                          ?._failed || 0
                  }
                )
              )
            )
          },
          {
            check_runs_count: trxToJson.length
          }
        )

        if (failingTestsFound) {
          if (inputs.ignoreTestFailures) {
            core.warning(`Workflow configured to ignore test failures`)
          } else {
            core.setFailed('At least one failing test was found')
          }
        }

        core.setOutput('test-outcome', failingTestsFound ? 'Failed' : 'Passed')
        core.setOutput('trx-files', trxFiles)
        core.setOutput('report-prefix', inputs.reportPrefix)

        // Record successful action outcome
        recordActionOutcome('success', {
          total_tests: totalTests,
          failed_tests: failedTests,
          trx_files: trxFiles.length,
          test_outcome: failingTestsFound ? 'Failed' : 'Passed'
        })
      },
      {
        action: 'trx-parser',
        repository: process.env.GITHUB_REPOSITORY || 'unknown',
        workflow: process.env.GITHUB_WORKFLOW || 'unknown'
      }
    )
  } catch (error: unknown) {
    const errorMessage = (error as Error).message
    core.setFailed(errorMessage)

    // Record failed action outcome
    recordActionOutcome('failure', {
      error_message: errorMessage
    })
  } finally {
    // Always attempt to shutdown telemetry
    if (telemetryEnabled) {
      await shutdownTelemetry()
    }
  }
}

run()
