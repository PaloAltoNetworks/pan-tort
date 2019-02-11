from django.shortcuts import render

from pan_cnc.lib import cnc_utils
from pan_cnc.views import CNCBaseFormView
from .pan_tort import process_hashes


class tortView(CNCBaseFormView):
    # define initial dynamic form from this snippet metadata
    snippet = 'run_tort'

    def get_snippet(self):
        return self.snippet

    # once the form has been submitted and we have all the values placed in the workflow, execute this
    def form_valid(self, form):
        workflow = self.get_workflow()

        # get the values from the user submitted form here
        query_tag = workflow.get('query_tag')
        hashes = workflow.get('hashes')
        output_type = workflow.get('output_type')
        api_key = workflow.get('api_key')
        payload = {
            'query_tag': query_tag, 'hashes': hashes,
            'output_type': output_type, 'api_key': api_key}
        tortHost = cnc_utils.get_config_value("TORT_HOST", "localhost")
        tortPort = cnc_utils.get_config_value("TORT_PORT", 5010)

        resp = process_hashes(payload)
        print(f"The response is: {resp}")
        # resp = requests.post(f'http://{tortHost}:{tortPort}', data=payload)
        # print(resp.headers)

        results = super().get_context_data()
        results['results'] = resp

        return render(self.request, 'pan_cnc/results.html', context=results)
