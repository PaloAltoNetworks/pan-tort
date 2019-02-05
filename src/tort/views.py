
from pan_cnc.views import CNCBaseAuth, CNCBaseFormView, ProvisionSnippetView
from pan_cnc.lib import cnc_utils
import requests

class tortView(CNCBaseFormView):
    
    
    def generate_dynamic_form(self):

       # define initial dynamic form from this snippet metadata
        snippet = 'run_tort'
        # next_url = '/pantort/process_hashes'

        def get_snippet(self):
            return self.snippet

    # once the form has been submitted and we have all the values placed in the workflow, execute this
    def form_valid(self, form):
        workflow = self.get_workflow()
        
        # get the values from the user submitted form here
        query_tag = workflow.get('query_tag')
        hashes = workflow.get('hashes')
        output_type = workflow.get('output_type')
        payload = {'query_tag': query_tag,'hashes': hashes, 'output_type': output_type}
        tortHost = cnc_utils.get_config_value("TORT_HOST","localhost")
        tortPort = cnc_utils.get_config_value("TORT_PORT", 5010)
        
        resp = requests.post(f'http://{tortHost}:{tortPort}', data=payload)
        print(resp.headers)

        if resp.status_code == 200:
            if 'json' in content_type:
                return_json = resp.json()
                if 'response' in return_json:
                    result_text = return_json["response"]
                else:
                    result_text = resp.text

                results = dict()
                results['results'] = str(resp.status_code)
                results['results'] += '\n'
                results['results'] += result_text
                return render(self.request, 'pan_cnc/results.html', context=results)

            else:
                response = HttpResponse(content_type=content_type)
                response['Content-Disposition'] = 'attachment; filename=%s' % filename
                response.write(resp.content)
                return response
        else:
            results = super().get_context_data()
            results['results'] = str(resp.status_code)
            results['results'] += '\n'
            results['results'] += resp.text

            return render(self.request, 'pan_cnc/results.html', context=results)
