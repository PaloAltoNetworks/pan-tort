
from pan_cnc.views import CNCBaseAuth, CNCBaseFormView, ProvisionSnippetView
import requests

class tortView(CNCBaseFormView):
    
    
    def generate_dynamic_form(self):

       # define initial dynamic form from this snippet metadata
        snippet = 'run_tort'
        next_url = '/pantort/process_hashes'

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
        
        r = requests.post(f'http://{tortHost}:{tortPort}', data=payload)

        
        print('set device-group and template to firewall name')

        return super().form_valid(form)